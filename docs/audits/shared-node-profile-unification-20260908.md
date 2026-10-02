# Shared node-profile unification

The group strategies now use one runtime-scoped node profile registry. When an
outbound manager is available, its stable pointer identity selects the
registry and a strong owner reference prevents pointer reuse while the
registry is retained. Manager lifecycles are watched independently, so one
group or provider reload cannot close evidence still used by another group.
Manager-less legacy callers are process-scoped only when there is exactly one
active process registry. The registry is the single source for probe results
and transport-scoped passive failures; strategy-specific state is limited to
policy decisions:

- **Smart** owns site-aware scoring, breaker state, stickiness, and Zig/Go
  policy selection. Its probe and real data-plane observations use the same
  credential-aware `DialIdentity` result key.
- **URLTest** consumes the shared TCP latency profile and UDP/TCP passive
  availability. It no longer owns an independent UDP failure ledger.
- **LoadBalance** consumes the same profile and retains only round-robin,
  hash, and sticky-session mapping. Sticky records resolve by `DialIdentity`,
  never by a slice index or a weaker credential-free path identity.

`EndpointIdentity` is used only for admission serialization, so aliases and
credential variants cannot start duplicate probes while their health evidence
remains isolated. TCP and UDP passive failures have distinct keys, and TCP
passive evidence is additionally keyed by the actual address family (`tcp`,
`tcp/ipv4`, or `tcp/ipv6`). History invalidation uses the same network value,
so a failed IPv6 dial cannot erase IPv4 or generic TCP evidence. A real Smart,
URLTest, or LoadBalance failure is published to the shared passive ledger for
a short, bounded quarantine; a successful connection clears only that
transport/family's quarantine.

Selection keeps the layers explicit: `groupProfileBaselineAlive` only checks
fresh active TCP evidence, while `groupTransportAvailable` applies the
current TCP-family or UDP passive ledger. UDP selection therefore never
inherits a TCP passive quarantine, and TCP selection never inherits UDP
evidence. Dashboard sampling uses the requested probe target when one is
provided; group summaries also read the exact target key instead of choosing
the newest result from an unrelated URL.

`common/urltest.HistoryStorage` remains as a compatibility projection for the
dashboard and legacy API. It is not consulted by production group selection
when a profile registry is present. Provider health checks likewise continue
to publish their UI-compatible history because the provider package cannot
depend on group policy code; they are not used as Smart/URLTest/LoadBalance
selection truth.

The registry is retained across zero group references and is closed only after
all manager lifecycle contexts end (or when the process-scoped context ends).
Probe admission is bounded globally and single-flight per endpoint. Tests cover
process/runtime isolation, credential separation, provider refresh identity,
TCP address-family and UDP isolation, passive recovery, lifecycle retention,
and concurrent forced probe coalescing.
