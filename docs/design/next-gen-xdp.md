# Next-gen AF_XDP data plane

Audience: implementers continuing the optional AF_XDP fast path.
Baseline: eBPF data-plane v3 (`docs/ports/EBPF-DATAPLANE-V3-DESIGN.md`,
`common/ebpf/v3`). Prior ABI notes: commit `52c2a10f` on
`adaptive/beta12-smart-mem9`.

This document is the source of truth for AF_XDP work. TC v3 remains the
production routing plane. AF_XDP is an opt-in DIRECT-only accelerator.

## 0. Decisions

| ID | Decision |
|----|----------|
| C-1 | TC owns routing and proxy handoff (`bpf_sk_assign`). AF_XDP never replaces TC. |
| C-2 | AF_XDP may forward only **DIRECT / bypass-equivalent L2/L3** frames. Proxy, unseen, DNS-conflict, and must-control traffic always `XDP_PASS` into the kernel so TC can assign sockets. |
| C-3 | Map key/value layout (L1) and the bounded `(data, data_end)` parser (L2) are shared. The action layer (L3) and userspace runtime (L4) are not. |
| C-4 | `bpf_sk_assign`, `skb->mark`, and conntrack do not exist in XDP. Do not emulate them. |
| C-5 | Empty XSKMAP slots must fall back with `bpf_redirect_map(..., XDP_PASS)`. Never drop on a missing socket. |
| C-6 | Gain is small-packet PPS and tail latency, not bandwidth and not proxy throughput. Do not claim otherwise. |
| C-7 | Capability comes from the kernel `netdev` generic-netlink `NETDEV_A_DEV_XDP_FEATURES` attribute (or an equivalent kernel query), a real mode-specific program load/attach, and `bind()`. No driver or kind allow/deny list. |
| C-8 | Every probe or attach failure **falls back to TC**. Failure is never a process-exit or inbound-start error. |
| C-9 | Native zero-copy requires at least two queues. Generic/SKB copy mode may be selected only with `allow_copy_mode`; it is never silently substituted for an explicit mode. |
| C-10 | New modules are **Zig** (or Rust if a crate already existed). Do not add Go packages for this path. Do not compile eBPF/XDP on macOS. Linux CI or an isolated PVE lab only. |
| C-11 | **Never deploy this path to hosts 107 or 115.** Those machines are macvlan + single-queue and are production/canary gateways, not AF_XDP labs. |
| C-12 | Classify `HANDOFF` must not mean “userspace” for both hooks. Proxy handoff is TC-only. XDP redirect is DIRECT-only. |

## 1. Why this exists

v3 TC already keeps static DIRECT in the kernel (`TC_ACT_OK`) and sends proxy
flows to sing-box. That path is correct. AF_XDP is not a second router.

AF_XDP is justified only when:

1. The ingress NIC has native XDP, `NETDEV_XDP_ACT_REDIRECT`, and zero-copy XSK.
2. It has at least two RX queues.
3. The workload is small-packet DIRECT forwarding where per-packet TC/softirq
   cost dominates (DNS floods, short QUIC, SYN/ACK storms on already-classified
   DIRECT prefixes).

If those are false, keep TC. Bandwidth of large-flow DIRECT is already close to
Linux forwarding; pulling frames into UMEM and transmitting them again is
usually slower.

## 2. Non-goals

- No userspace TCP/UDP stack, gVisor, or proxy inbound rewrite.
- No Smart node selection in eBPF or XDP.
- No first-packet domain or weak-DNS DIRECT.
- No default UDP/443 drop.
- No AF_XDP on macvlan, veth, WireGuard, or any device whose feature bits or
  `bind()` fail.
- No production attach on 107 or 115.
- No macOS build, generate, or load of BPF/XDP objects.

## 3. Traffic boundary

```
                    packet
                      │
                      ▼
              L2 parser (shared)
                      │
                      ▼
           classify (hook-neutral)
                      │
        ┌─────────────┼──────────────────┐
        ▼             ▼                  ▼
     DIRECT         PROXY              DROP
        │             │                  │
        ▼             ▼                  ▼
  XDP: redirect    XDP: PASS          XDP_DROP
  to XSK only if   into kernel ──►    (explicit
  session attached  TC sk_assign      block only)
  else XDP_PASS
        │
        ▼
  userspace L2/L3 forward
  (no TCP terminate)
```

### 3.1 Verdict → XDP action

| Verdict | TC action | XDP action | Redirect to XSK |
|---------|-----------|------------|-----------------|
| DIRECT (static/flow/authoritative FakeIP) | `TC_ACT_OK`, mark 0 | `XDP_REDIRECT` if attached, else `XDP_PASS` | yes, DIRECT only |
| PROXY / UNSEEN / MUST_CONTROL | `sk_assign` / NEED_USERSPACE | **`XDP_PASS` only** | **never** |
| BLOCK | `TC_ACT_SHOT` | `XDP_DROP` | never |
| security / DHCP / ND / mcast / established | `TC_ACT_OK`, mark 0 | `XDP_PASS` | **never** (must hit kernel) |
| parse fail / fragment / generation miss | NEED_USERSPACE | `XDP_PASS` | never |

The older “one HANDOFF maps to TC `sk_assign` and XDP `redirect_map`” sketch is
rejected. That would dump proxy frames onto AF_XDP sockets that cannot
terminate TCP.

### 3.2 Fail-open

| Event | XDP result |
|-------|------------|
| program not attached | kernel/TC unchanged |
| XSKMAP slot empty | `XDP_PASS` (flag on `bpf_redirect_map`) |
| UMEM fill starved | count `fill_starved`, do not drop as policy |
| probe fail / bind fail / queue < 2 | stay on TC, log, continue |
| link/MTU/queue change | detach, fallback TC, re-probe |
| ABI or generation mismatch | `XDP_PASS` |

Map miss is **proxy**, not DIRECT. Fail-open means “give the packet to TC /
kernel”, not “forward it unexamined”.

## 4. Layers

```
xdp-engine/          Zig: classify, probe matrix, lifecycle (this repo)
common/ebpf/native/  future C: shared parser + hook_xdp.bpf.c (Linux only)
TC v3                unchanged production path
```

| Layer | Shared? | Contents |
|-------|---------|----------|
| L1 maps | yes | v3 control, LPM policy, flow verdict, DNS hint. No XDP-specific keys in policy maps. |
| L2 parser | yes | `(data, data_end)` only. Multi-buffer XDP (`RX_SG` / `bpf_xdp_get_buff_len`) must `XDP_PASS` until a bounded multi-segment parse exists. |
| L2.5 classify | yes, pure | verdict + reason. Unit-tested without a kernel. |
| L3 XDP actions | no | `XDP_PASS` / `DROP` / `REDIRECT`. No mark. |
| L3 TC actions | no | existing v3 `hook` / `sk_assign`. |
| L4 AF_XDP runtime | no | `xdp-engine/src/linux_adapter.zig`: bounded UMEM, four rings, per-queue XSK, poll, TX and completion return. The host still owns policy-map publication and attach ordering. |

## 5. Probe (zero driver knowledge)

Four tiers. Kind/driver names appear only in diagnostic logs.

| Tier | Input | Fail action |
|------|-------|-------------|
| 0 | `netdev` generic-netlink `NETDEV_A_DEV_XDP_FEATURES` | missing `REDIRECT` or `XSK_ZEROCOPY` → fallback TC. Absent family/attribute (old kernel) → skip to Tier 1. `RX_SG` set → fallback TC until the bounded segment parser exists. |
| 1 | `bind(XDP_ZEROCOPY)` then optional `XDP_COPY` | both fail → fallback TC. Copy-only succeeds → fallback TC unless `allow_copy_mode`. |
| 2 | RX queue count | `< 2` → fallback TC. |
| 3 | `RTM_NEWLINK` | queue/MTU/driver reset → detach + re-probe. |

Admission for native zero-copy attach: `REDIRECT | XSK_ZEROCOPY`, queues ≥ 2,
ZC bind OK, and no RX scatter-gather. Generic/SKB admission is a separate
copy-mode probe and requires `allow_copy_mode`. Hardware/offload admission requires the same object to pass
the NIC's offload verifier; feature bits alone never enable it. No hardcoded
macvlan/veth blacklist: those devices already report 0 bits or fail `bind()`.

## 6. Lifecycle

```
disabled → probing → attached_zc
                 ↘ attached_copy (only allow_copy_mode)
                 ↘ fallback_tc
attached_* → detaching → probing | fallback_tc | disabled
```

Invariants:

- Classify and probe are allocation-free after init.
- Host serializes probe/attach/detach. The Zig core holds no locks and no
  global mutable session.
- Close always reaches `disabled` and releases UMEM/rings; a failed detach
  still leaves TC as the live path.
- Reload of sing-box policy generation does not require XDP re-bind. Stale
  flow/DNS hits miss generation and `XDP_PASS`.
- Memory: UMEM frame size and count are compile-time constants, clamped.
  Frame count does not grow with Smart node count or connection count.

Suggested bounds (skeleton constants, overridable later):

| Resource | Default | Clamp |
|----------|---------|-------|
| UMEM frame size | 2048 | 2048–4096 |
| UMEM frames | 4096 | 512–16384 |
| queues handled | NIC count | ≤ 64 |
| XSKMAP slots | queues | = queues |

## 7. Portability and build

- Zig 0.14, `-Dcpu=baseline`, same pattern as `smart-engine/`.
- Tests: `zig build test -Dcpu=baseline` on Linux CI (`ubuntu-latest`).
- BPF object generate/load: Linux builders or isolated PVE with clang, BTF,
  and multi-queue NICs. Not macOS. Not 107. Not 115.
- Do not add this crate/engine to the Darwin/Windows Go test matrix.
- Cross-compile of the Zig library for `x86_64-linux-gnu` and
  `aarch64-linux-gnu` is allowed on Linux CI; it is not an eBPF load test.

## 8. Configuration (future, not wired in this change)

```json
{
  "type": "ebpf",
  "shared_network": {
    "enabled": true,
    "engine": "v3",
    "data_plane": "socket_assign",
    "xdp": {
      "enabled": false,
      "mode": "auto",
      "allow_copy_mode": false
    }
  }
}
```

Default `xdp.enabled` is false, and v3 migration rejects `true` until the
Linux host adapter is wired. `data_plane` stays `socket_assign`. A later
`data_plane: "afxdp"` may enable the DIRECT accelerator **in addition to** TC
proxy, never instead of it. `mode: "auto"` probes hardware offload first,
then native/driver, then generic/SKB; each candidate must pass the real
verifier/attach and AF_XDP bind probe. Explicit `skb`, `native`, or `offload`
fails open to TC instead of selecting a different mode.

## 9. Phasing

| Phase | Deliverable | Status |
|-------|-------------|-------------|
| 0 | Design + acceptance matrix + Zig classify/probe/lifecycle skeleton | **yes** |
| 1 | Shared parser/policy ABI plus original XDP kernel object and Linux mode-aware loader (no default behavior change) | **yes** |
| 2 | Linux-only probe syscalls behind the Zig matrix | **mode-aware loader + real XSK bind adapter; privileged attach remains host-owned** |
| 3 | UMEM / rings / poll (Linux, lab NIC) | **Zig Linux adapter implemented; privileged lab forwarding evidence pending** |
| 4 | `hook_xdp.bpf.c` + verifier load on lab kernels | **object + CI verifier surface yes; privileged lab load pending** |
| 5 | Multi-queue physical A/B: bandwidth **and** 64B/128B PPS | no |

The checked-in loader still leaves XDP disabled until a host has bound every
selected queue. The standalone Zig adapter now performs bounded UMEM/ring
setup and exposes a C ABI, but sing-box integration must still publish all
XSK FDs and enable the control record only after the adapter reports ready.
CI builds and inspects the object; a privileged multi-queue lab is required
before enabling the forwarding adapter.

The required hand-off is now explicit: `probe_bind` → mode-specific program
probe/attach → open/bind all queues → publish each XSKMAP entry → enable the
separate control record. A missing step leaves XDP disabled and TC active. The
Go control plane is not linked to this library yet; this is deliberate until a
Linux lab demonstrates bidirectional DIRECT forwarding and link-change
rollback with real traffic.

## 10. Hard prohibitions

1. Do not `bpf_sk_assign` from XDP.
2. Do not set `skb->mark` on PASS/DROP/fail-open (TC already forbids this; XDP
   has no mark and must not invent one).
3. Do not redirect PROXY/UNSEEN/MUST_CONTROL to XSK.
4. Do not `bpf_redirect_map` without `XDP_PASS` empty-slot flags.
5. Do not keep irrecoverable state in LRU.
6. Do not use driver/kind lists as admission.
7. Do not enable AF_XDP on one queue.
8. Do not add a userspace TCP stack.
9. Do not advertise proxy or bulk-bandwidth wins.
10. Do not treat bind as a one-shot fact (Tier 3).
11. Do not add legacy `bpf_map_def`.
12. Do not fail inbound start because XDP probe failed.
13. Do not compile or generate on macOS.
14. Do not deploy to 107 or 115.

## 11. Acceptance matrix

Status values: `lock` = encoded in Zig tests; `ci` = Linux build/object gate; `lab` = Linux kernel/NIC;
`gate` = isolated PVE canary that is **not** 107/115; `out` = not this repo
change.

### 11.1 Boundary and classify (`lock` + `ci`)

| ID | Requirement | Evidence |
|----|-------------|----------|
| A-1 | Static DIRECT may redirect only when the XDP session is attached. | `xdp-engine` test `static direct redirects only when attached` |
| A-2 | Map miss / unseen is PROXY and `XDP_PASS`, never redirect, never DROP. | `map miss never redirects` |
| A-3 | Explicit PROXY verdict never redirects even if attached. | `proxy verdict never redirects` |
| A-4 | MUST_CONTROL / DNS conflict never DIRECT or redirect. | `dns conflict must control` |
| A-5 | Parse failure is `XDP_PASS`, mark unused, no redirect. | `parse fail passes to kernel` |
| A-6 | IP fragment is never first-packet DIRECT/redirect. | `fragment never first-packet direct` |
| A-7 | UDP/443 is not dropped unless the explicit flag is set. | `udp 443 not dropped by default` |
| A-8 | DHCP/ND/broadcast/multicast always `XDP_PASS`, never XSK. | `security bypass never redirects` |
| A-9 | Established TCP always `XDP_PASS` (kernel owns the socket). | `established tcp never redirects` |
| A-10 | Weak DNS hint is never first-packet DIRECT. | `weak dns hint is proxy` |
| A-11 | Generation mismatch is PROXY/`XDP_PASS`. | `generation miss is proxy` |
| A-12 | Empty-slot redirect flags equal `XDP_PASS` (2), not DROP/ABORTED. | `redirect empty slot uses xdp pass` |
| A-13 | IPv4/IPv6 and TCP/UDP share the same verdict mapping. | table tests in `classify.zig` |
| A-14 | Classify allocates nothing and uses no locks. | code inspection + no allocator in `classify.zig` |
| A-15 | A clean TCP SYN may redirect; ACK/FIN/RST always PASS. | Zig model + `xdp.bpf.c` flags gate |
| A-16 | XDP ABI/control generation and active bank must match TC before redirect. | `xdp.bpf.c` |

### 11.2 Probe and fallback (`lock`)

| ID | Requirement | Evidence |
|----|-------------|----------|
| P-1 | Missing `REDIRECT` bit → fallback TC, not attach. | `probe.zig` |
| P-2 | Missing `XSK_ZEROCOPY` → reject only the zero-copy bind; an explicitly allowed generic/SKB copy bind may still attach. | `probe.zig` |
| P-3 | RX queues < 2 → reject zero-copy; generic/SKB copy mode requires at least one queue and may proceed when explicitly allowed. | `probe.zig` |
| P-4 | ZC and copy bind both fail → fallback TC. | `probe.zig` |
| P-5 | Copy bind only → fallback TC unless `allow_copy_mode`. | `probe.zig` |
| P-6 | `RX_SG` set → fallback TC; the current one-descriptor parser never redirects a scatter-gather frame. | `probe.zig` + XDP control guard |
| P-7 | Absent feature bitmap skips Tier 0 and uses bind + queues. | `probe.zig` |
| P-8 | No probe result is “fatal/exit”. | `ProbeResult.fatal == false` always |
| P-9 | Kind/driver strings are not consulted. | no such fields on `ProbeSample` |
| P-10 | Auto mode prefers verified offload, then native, then generic; no silent downgrade for explicit modes. | `selectMode` tests |

### 11.3 Lifecycle and memory (`lock` + `ci`)

| ID | Requirement | Evidence |
|----|-------------|----------|
| L-1 | Probe fail moves `probing` → `fallback_tc`, never `attached_*`. | `lifecycle.zig` |
| L-2 | Link change from attached goes `detaching` then `fallback_tc` (host re-probes). | `lifecycle.zig` |
| L-3 | `close` always ends in `disabled` and clears attach flags. | `lifecycle.zig` |
| L-4 | Copy attach is refused unless `allow_copy_mode`. | `lifecycle.zig` |
| L-5 | UMEM bounds are constants and do not grow with node/session count. | `model.zig` |
| L-6 | Session is a value type; no heap, no global. | `lifecycle.zig` |
| L-7 | Host must serialize attach/detach (documented; core is not thread-safe). | this section + README |
| L-8 | RX/TX/completion ownership is bounded; full peer TX returns to kernel. | `afxdp.zig` ring tests |
| L-9 | Shared UMEM has one fill/completion ring sized for the bounded total frame budget; frames can be received by any queue and are recycled through the shared ring without duplicate descriptors or double-unmap on close. | `linux_adapter.zig` ownership table + Linux CI build |

### 11.4 Portability (`lock` + `ci`)

| ID | Requirement | Evidence |
|----|-------------|----------|
| O-1 | New code is Zig under `xdp-engine/`, not Go. | tree |
| O-2 | Linux CI runs `zig build test -Dcpu=baseline` on Ubuntu only. | `.github/workflows/xdp-engine.yml` |
| O-3 | Workflow does not run on macOS or Windows. | `runs-on: ubuntu-latest` |
| O-4 | Baseline CPU, matching `smart-engine`. | `build.zig` |
| O-5 | No BPF `.o` generate on Darwin. | Linux-only `bpf` workflow job |
| O-6 | XDP object has BTF/maps and a provenance hash; stale object fails. | `xdp-generate`, `xdp-check`, `check-xdp-source` |

### 11.5 Lab / gate (required before production)

| ID | Requirement | Evidence |
|----|-------------|----------|
| K-1 | Committed XDP object loads on Debian PVE lab kernel (not 107/115). | `lab` |
| K-2 | Verifier reject → leave TC attached, inbound still starts. | `lab` |
| K-3 | `ethtool -L` queue change detaches XDP; traffic continues on TC. | `lab` |
| K-4 | Google 204 and a DIRECT CIDR still work with XDP disabled. | `gate` on a non-107/115 host |
| K-5 | Multi-queue physical A/B reports bandwidth **and** 64B/128B PPS vs TC. Bandwidth flat is OK; PPS must improve to adopt. | `lab` |
| K-6 | `fill_starved == 0` for 10 minutes on the lab NIC. | `lab` |
| K-7 | Proxy path p95 does not regress > 5% vs TC-only. | `lab` |
| K-8 | **Do not run K-* on 107 or 115.** | ops rule |
| K-9 | Exercise generic, native and (when hardware accepts it) offload attach on the same policy object. | privileged lab |
| K-10 | Attach both interfaces and forward both directions; link/queue change detaches and TC continues. | privileged lab |
| K-11 | XSK fill/completion starvation, MTU, VLAN, IPv4/IPv6 and malformed frames all fail open. | privileged lab |

### 11.6 Explicit non-acceptance

| ID | Claim | Result |
|----|-------|--------|
| N-1 | AF_XDP improves proxy throughput | rejected |
| N-2 | AF_XDP improves bulk DIRECT bandwidth vs kernel forward | not a pass criterion |
| N-3 | Deploy to 107/115 because kernel ≥ 6.11 | rejected (macvlan + 1 queue) |
| N-4 | macOS compile validates XDP | rejected |

## 12. Code layout (Phase 1)

```
docs/design/next-gen-xdp.md     this file
xdp-engine/
  README.md
  build.zig
  src/model.zig                 verdicts, XDP actions, bounds
  src/classify.zig              hook-neutral classify + XDP mapping
  src/probe.zig                 Tier 0–2 matrix
  src/lifecycle.zig             state machine
  src/afxdp.zig                 bounded RX/TX/completion ownership
  src/lib.zig                   facade + test root
.github/workflows/xdp-engine.yml

common/ebpf/v3/kern/xdp.bpf.c   original XDP ingress policy hook
common/ebpf/v3/kern/xdp_*.h    XDP-only ABI and map declarations
common/ebpf/native/xdp_runtime.c Linux loader/mode attach lifecycle
```

No Go XDP policy code and no production host deploy script are permitted.

## 13. Relationship to v3 TC tests

`go test ./common/ebpf/v3 ./protocol/ebpf/v3` remains the TC production gate.
Phase 0 must not change those packages. If a future C parser extraction
touches them, it is a separate change with the existing v3 decision tests as
the regression lock.
