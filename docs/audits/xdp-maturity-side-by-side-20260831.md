# XDP maturity side-by-side review (2026-08-31)

## References

- [Linux AF_XDP documentation](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [xdp-tools/libxdp](https://github.com/xdp-project/xdp-tools)
- [libxdp dispatcher protocol](https://github.com/xdp-project/xdp-tools/blob/main/lib/libxdp/protocol.org)
- [Katran](https://github.com/facebookincubator/katran)

## Comparison

| Area | Our XDP engine | Mature reference behavior | Assessment |
|---|---|---|---|
| Ring ownership | Shared UMEM FILL/COMPLETION, per-queue RX/TX, bounded frame states | Linux AF_XDP uses one FILL/COMPLETION pair per UMEM and SPSC rings | Semantics aligned; ownership and overflow are explicitly bounded |
| Wakeups | `XDP_USE_NEED_WAKEUP`; TX syscall and FILL-ring poll on the flagged path | Kernel recommends polling/send only when the need-wakeup bit is set | Correct after `0384a24d`; no unconditional syscall loop |
| Queue readiness | XSKMAP is enabled only after every selected queue is bound | Production loaders validate queue/device state before activation | Conservative and fail-open |
| Attach coexistence | Exclusive attach; refuses an existing XDP program | libxdp uses an atomic dispatcher for multiple programs | Safe, but not interoperable with an existing dispatcher yet |
| Modes | Explicit `skb`, `native`, `offload`, plus verified `auto` ordering | xdp-loader supports native, skb, hw and unspecified selection | Mode model is comparable; hardware behavior still needs a real NIC |
| Fragments | RX scatter-gather/XDP frags deliberately falls back to TC | libxdp dispatcher and modern programs propagate XDP frags metadata | Safe feature gap; MTU/SG acceptance is not claimed |
| Data-plane scope | DIRECT-only frames; proxy/unknown traffic remains TC | Katran is an in-kernel forwarding plane; AF_XDP samples own the packet loop | Correct for our proxy architecture; not a general userspace stack |
| Runtime integration | Zig/C adapter and C loader are production-shaped, but Go migration still rejects `xdp.enabled` | Mature projects have a privileged attach, poll, metrics and rollback loop | Main release blocker for AF_XDP, not for TC v3 |
| Verification | Linux CI: Zig tests, C ABI, BPF sections/policy, Go race/vet and four-arch builds | Mature projects additionally exercise real NICs, queue churn and bidirectional traffic | Code gates are green; environmental acceptance is still required |

## Verdict

The implementation is materially safer than a prototype: it has bounded memory,
explicit ownership, mode verification, fail-open TC fallback, attach exclusivity,
and no silent frame loss when a peer TX ring is full. It is suitable for the
existing TC v3 production path and for an isolated AF_XDP integration test.

It is **not yet equivalent to a mature general-purpose XDP stack**. Before
enabling AF_XDP in a production host, the following must be completed:

1. Wire the adapter into the host control loop so `ready=false`, ring pressure,
   link changes, and close immediately disable the XDP control record and return
   to TC.
2. Run a privileged test on an XDP-capable multi-queue NIC (or SR-IOV VF) with
   bidirectional DIRECT traffic, queue loss/re-add, restart, and link-change
   rollback. Include copy/native/offload selection and packet-loss counters.
3. Either implement libxdp-compatible dispatcher coexistence or document and
   enforce an exclusive-interface contract at deployment time.
4. Add bounded XDP-frags support or retain the current explicit TC fallback for
   jumbo/scatter-gather interfaces.

VM115 remains TC-only: its guest kernel has global XDP support and two virtio
queues, but the device-scoped probe fails; the PVE uplink is a single `tg3`
interface. Rebuilding the same guest kernel cannot satisfy the missing device
and host integration gates.

## Current evidence

- Global Smart/eBPF audit: GitHub Actions `33321506619` — passed.
- XDP engine: GitHub Actions `33321506609` — passed.
- Final Linux release matrix: GitHub Actions `33321595817` — passed for
  amd64/arm64 × glibc/musl; publication was disabled.
- Latest source commits: `0384a24d` (attach/wakeup hardening), `b7598c52`
  (Zig C-ABI pointer fix), and `dcb4782c` (115 capability evidence).

No XDP program was attached to VM107 or VM115 during this review.
