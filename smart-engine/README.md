# Portable Smart policy engine

This directory contains the dependency-free Smart decision core written in Zig.
It has no sing-box, mihomo, Provider, socket, DNS, or platform dependencies.
The C ABI in `include/smart_engine.h` is the portability boundary for Go,
Rust, mihomo, or another host core.

The core owns only bounded metrics, score calculation, unified stable
primary/backup affinity selection, switch margin, confirmation samples/time,
cooldown, and deterministic state transitions. The
implementation is split into `model.zig`, `metrics.zig`, `scoring.zig`, and
`policy.zig`; `adaptive.zig` contains the AdaptivePool ordering kernel and
`lib.zig` is only the C ABI facade. The observation store keeps a
fixed 4096-entry metric payload behind an 8192-slot open-addressing index, so
normal observe/get operations are expected O(1), eviction is bounded, and reset
cannot retain a large hash-map backing allocation.

`smart_engine_choose_profile` exposes interactive, bulk and UDP weighting; the
original choose function remains an interactive-compatible entry point.

The versioned ABI carries the complete policy set: exploration, relative and
absolute latency thresholds, confirmation/cooldown, healthy-incumbent site
stickiness, and unified primary/backup affinity selection.
`smart_engine_set_selected`
is called only after a real dial succeeds, so stickiness never hides a failed
initial connection. Probe scheduling, provider filters, breakers, and
connection interruption remain host-owned by design.

After a hard failure, the displaced ID is retained as a deferred backup. A
recovered endpoint cannot preempt the replacement primary; it is eligible
again only when the current primary becomes unusable. This rule applies to
the unified policy, so dispersion is per business context, not per connection.
`smart_engine_adopt_selected` restores
the host-confirmed primary when a bounded context is recreated without
overwriting an in-flight policy challenge.

The optional `conformance/` package is built by Linux CI with the `smart_zig`
tag. It links the produced library through the C ABI and compares the
transition sequence with a Go reference. Production release jobs compile the
same library for each Linux architecture/libc pair before building sing-box.

The host owns node discovery, EndpointProfile/health evidence, dialing,
persistence, logging, and API compatibility. This prevents the policy engine
from opening sockets or reimplementing Provider logic. AdaptivePool uses the
same boundary: pin/lease/failure evidence is supplied by Go, while adaptive,
strict-affinity, latency, and bulk ordering/rotation are decided by Zig. The
Go adapter reuses a
candidate batch buffer per lock shard (16 shards, four bounded contexts each),
so cgo conversion allocations are amortized without retaining a large buffer
per context. The reference Go policy remains available for zero-dependency
development. Production builds add `smart_zig,production_smart`; the latter
makes a missing Zig ABI fail closed instead of silently selecting through the
Go policy. Production `smart_zig` builds use the same Zig ABI
for all legacy selection mode spellings.

Build and test with Zig 0.14+:

```sh
zig build test -Dcpu=baseline
zig build -Dcpu=baseline -Doptimize=ReleaseFast

Release builds intentionally use the portable `baseline` CPU profile.  Use
`-Dcpu=native` only for a deployment whose CPU feature set is controlled.
```

Linux release builds select Zig with `smart_zig` and link the matching static
library. The release adapter rejects an ABI mismatch or engine allocation
failure instead of falling back to the duplicate Go policy state machine; this
keeps one production decision owner. Manual pins, EndpointProfile, failure
wakeups, and switch auditing remain host-owned. A `smart_zig` build without cgo
fails closed. Adaptive ABI changes are versioned
(`ADAPTIVE_ENGINE_ABI_VERSION`) and old libraries are rejected before use.
