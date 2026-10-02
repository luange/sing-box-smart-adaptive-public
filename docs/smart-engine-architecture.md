# Smart Engine architecture

## Decision

Smart is split into a host-neutral policy kernel and a host adapter. The
kernel is the Zig library in `smart-engine/`; the adapter remains responsible
for sing-box or mihomo integration. The kernel never opens sockets, resolves
DNS, reads providers, persists state, emits logs, or owns API objects.

The boundary is a versioned C ABI. Hosts provide a bounded candidate snapshot
(`id`, health evidence, latency, jitter, throughput, weight and eligibility)
and report observations. The kernel returns a decision plus a reason. This
keeps provider refreshes and core-specific object lifetimes outside the policy
code, so a future mihomo adapter can reuse the same binary and tests.

The ABI has an additive profile entry point for interactive, bulk and UDP
traffic. The original `smart_engine_choose` remains interactive for older
hosts; unknown profile values fall back to interactive scoring.

## Modules

- `model.zig`: ABI-safe data types and state constants.
- `metrics.zig`: fixed-capacity, allocation-free observation table. Entries are
  evicted by oldest update when the limit is reached; an open-addressing index
  makes normal lookup expected O(1), and reset releases no hidden map capacity.
- `scoring.zig`: pure reliability/tail-latency/jitter/weight scoring functions.
- `policy.zig`: incumbent retention, margin, confirmation and cooldown state
  transitions. It has no I/O and is deterministic for `(snapshot, now)`.
- `lib.zig`: thin lifecycle and C ABI facade.

The Go implementation remains a zero-dependency development/reference path for
ordinary upstream builds. Linux release builds select the in-process Zig
adapter with the `smart_zig` build tag after the same conformance gate; provider,
routing, and API code are unchanged. In a `smart_zig` release, Smart
construction fails if the Zig ABI is missing or incompatible instead of
silently falling back to the Go policy. This makes Zig the only production
decision kernel.

Zig deliberately does not open sockets or duplicate sing-box protocol code.
The Go host remains the network-I/O adapter that performs the actual TCP/UDP
probe and reports observations over the small ABI. “Zig-only” therefore means
one policy/selection owner, not a second DNS/TLS/proxy stack. The unified
stable primary/backup affinity policy is implemented inside the versioned ABI;
a Zig release never silently runs a Go selector.

The Go adapter sends candidates through the existing batch ABI entry point and
reuses one conversion buffer per lock shard (16 shards, four bounded contexts
each). Different service contexts can rank concurrently without retaining a
large candidate buffer per context.

### Parameter ownership and parity

The Zig ABI receives every parameter that changes a selection decision:
`exploration`, `switch_margin`, `switch_confirm_samples`, `switch_confirm`,
`switch_cooldown`, `switch_min_improvement`, `site_stickiness`, and
numeric `mode`, and the configured `min_samples` confidence floor. Candidate `weight`, health state, reliability, p95 connect /
first-byte latency, jitter, throughput, sample count, and eligibility are sent
in each bounded snapshot. ABI version 5 is required when this layout changes.

The remaining Smart options are intentionally host-owned and are not missing
ABI fields: URL/probe interval, probe concurrency and timeout, dial attempts,
stall observation, breaker and half-life storage, passive throughput gating,
provider/catalog filters, manual pins, connection interruption, and history/API
limits. They perform I/O, lifecycle, or evidence preparation before the Zig
kernel is called. Keeping them out of Zig avoids a second scheduler or a second
health store. The host and Zig scoring paths use the same p95 latency order,
half-open penalty, confidence prior, and exploration formula.

## Passive bulk throughput signal

Bulk candidates can be bypassed after the configured number of real-traffic
throughput observations falls below `passive_throughput_floor_bps` (default
512 KiB/s, two observations). This signal never fetches a probe resource,
never interrupts an existing stream, and never makes a reachable endpoint
ineligible. Bulk scoring and status reporting use it after the sample count;
only connection or protocol failures can open a circuit. Service-local
throughput takes precedence over global history, so a slow YouTube path cannot
be hidden by unrelated traffic.

## Phased startup and stable selection

Smart does not block the first user connection on a full candidate test. The
worker moves through `cold` → `baseline` → `profiling` → `steady`: the first
successful basic probe (or real dial) publishes a usable candidate immediately;
subsequent bounded cycles build the remaining portraits; performance-driven
switches are enabled only after profiling evidence exists. Hard dial failures
still fail over immediately in every phase. During cold/baseline, the hedge
delay is shortened to 250 ms so a bad first guess is abandoned quickly without
starting a full parallel probe storm; a well-sampled steady path keeps the
longer delay to protect keep-alive traffic.

Smart exposes exactly two primary-selection modes through the numeric `mode` field:

- `1` (default): apply A/B/C health bands and disperse eligible near-tied
  candidates using stable context ordering. Hard failures still
  fail over immediately. PBR remains the boundary between regional Smart
  groups, and the mode never selects outside its configured candidate pool.
- `0`: retain the healthy incumbent and use another candidate only when
  the incumbent becomes unusable. This is the stable single-egress option for
  long-lived sessions and services that require one IP.

Omit `mode` for the default `1`, or set `"mode": 0` to opt into fixed-primary
behavior. The older string `selection_mode` remains accepted for existing
configurations but should not be used in new configurations.

Example:

```json
{
  "type": "smart",
  "tag": "media-smart",
  "outbounds": ["hk-1", "jp-1", "sg-1"],
  "mode": 1
}
```

To keep one healthy primary until failure, change only the mode:

```json
"mode": 0
```

The normal configuration does not require any of these policy details: a Smart
group with only `outbounds`/`providers` uses the built-in probe budget, phase
transitions, margins, confirmation and cooldown defaults. Advanced fields remain
compatibility overrides for operators who already use them; the staged startup
is intentionally internal so a new deployment does not need to guess a
 ”correct” tuning value. The Zig policy backend owns the confirmation state for
the unified policy. A production release does not silently switch to the host
adapter.

TCP and UDP background coverage are independent. TCP uses its used/stale
candidate budget, while UDP serializes at most two DNS reachability probes per
cycle and rotates by never-probed or least-recently-probed EndpointProfile.
Provider aliases share one UDP budget slot, and a failed attempt advances the
UDP cursor just like a successful one. Registry cache hits are usable evidence
for the caller but do not advance fresh UDP coverage, so a large group is
eventually sampled without creating a probe storm or leaving UDP-only lines in
an `unknown` state forever. Cold starts use a four-candidate batch, active
periodic cycles use a bounded sixteen-candidate batch, and idle cycles continue
with a one-candidate maintenance batch; repeated cycles therefore form a full
catalog sweep without blocking the first request.

All Smart active measurements enter one probe executor with an explicit
purpose. Background portrait maintenance and TCP/UDP family coverage may add
health evidence and refresh ranking; outage recovery bypasses the cadence cache
but retains endpoint single-flight; dashboard delay requests are advisory and
may return/refresh latency only. A dashboard request cannot penalize a node,
open or close a breaker, publish the latest selection context, or release a
manual pin. The shared registry, rather than each caller, owns cache reuse,
per-endpoint serialization and process-wide admission.

On Linux, Smart reads `TCP_INFO` once when a TCP connection closes and records a
bounded retransmitted-byte ratio. It contributes an additive latency penalty
(1% ≈ 50 ms, capped) rather than opening a circuit; unsupported platforms and
non-TCP transports simply omit this evidence.

## Established stream stall observation

After a successful dial, Smart arms one runtime timer for each request phase
only when the caller actually writes. This continues after the first response,
so an established keep-alive connection that accepts a new request but stops
responding is observable. If no response byte arrives before
`established_stall_timeout` (default 10s, bounded to 5s–2m), the connection
contributes one failure observation and wakes the shared probe registry. Any
response byte or close cancels the pending phase timer; idle WebSockets and
normal long-lived streams are therefore not penalized. This is passive and
does not generate traffic; the existing per-connection failure-once gate also
coalesces a later socket error.

The Clash status extension exposes a bounded `contexts` array (at most 32)
with independent network/site/transport snapshots. Legacy top-level fields
remain the most recently updated context for older dashboards.

Related subservices use a hierarchical identity. The endpoint portrait is the
shared baseline and each subservice keeps an independent health ledger, while
one parent-business Zig context owns the incumbent for all of its domains and
transports inside the Smart group. For example, ChatGPT Web and the OpenAI API
use one OpenAI primary; Telegram domain and officially published address
ranges use one Telegram primary. A site-local or transport-local failure is
evaluated against its own evidence, then a successful fallback is promoted as
the business primary. This preserves a stable egress identity without letting
one site's failure counters contaminate another site or transport.

Business identity is evidence-driven rather than tied to one sniffer. Known
SNI/HTTP Host semantics are authoritative; an application classifier may fill
an IP-only flow using a stable label such as `k3:telegram`; service-published
address ranges are the final fallback. Generic transport labels (`tls`,
`quic`) never become a business identity. All three inputs converge before
selection and cannot bypass candidate capability, health, breaker, or manual
pin gates.

## Invariants and evolution

Candidate IDs are stable endpoint identities, not provider display names.
Only eligible, non-open candidates can be selected. A current candidate is
retained unless the relative improvement exceeds `switch_margin`, the p95
latency improves by at least `switch_min_improvement` (default 100ms), the new
candidate is observed for the configured confirmation count and time, and the
cooldown has elapsed. Hard-open candidates are removed before weights are
applied, so a large manual weight cannot resurrect a failed endpoint.

Interactive scoring uses 30% reliability, 25% p95 connect, 30% p95 first byte,
10% jitter and 5% sample confidence. Bulk keeps 30% throughput weight, while
UDP gives reliability and jitter priority. The host stores a bounded tail-EWMA
instead of a per-node sample ring; old snapshots transparently fall back to
their EWMA values. Provider display-name copies resolve to one endpoint
portrait, while the dashboard still shows both the EWMA and p95 values.

New evidence fields must be appended to the ABI or introduced with an ABI
version; existing field order and enum values are never reused. Any host
integration must add deterministic parity tests before production enablement.

## Alternatives rejected

- A full Zig proxy rewrite would duplicate sing-box protocol, DNS, TLS and
  platform code, creating a large compatibility surface and a long migration
  period. It is not justified by Smart's policy workload.
- A subprocess policy daemon would be portable but adds IPC latency, failure
  recovery and another long-lived process to operate. The in-process library
  keeps one bounded state owner.
- Zig eBPF bindings are not a prerequisite here. The data plane and its kernel
  ABI remain separate; Smart receives evidence only. This avoids coupling a
  policy release to kernel/BTF support.

## Rollout gates

1. Linux CI builds and tests the Zig library, links a C ABI smoke harness, and
   cross-builds amd64 and arm64 libraries.
2. A Go reference adapter feeds identical snapshots and compares every
   decision/reason transition, including empty and over-limit inputs.
3. A canary host enables the release binary's `smart_zig` backend and records
   switch audits, RSS and latency for at least 72 hours.
4. ABI mismatch or allocation failure fails Smart construction/ranking closed
   with an explicit error; provider refresh, DNS and routing behavior remain
   unchanged.
