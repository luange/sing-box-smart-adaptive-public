# RC4 global audit gate (2026-08-30)

This branch is based on official sing-box `v1.14.0-rc.4`. The global gate
keeps the four moving parts separate:

- Smart/Adaptive state and provider refreshes remain bounded, endpoint-scoped,
  and covered by Go race tests.
- eBPF v3 remains the production TC/socket-assign path; policy generations,
  DNS hints, and flow learning are tested without enabling AF_XDP.
- Smart Zig and the XDP Zig policy/adapter are built on Linux only, with
  x86_64 and aarch64 cross-builds and C ABI smoke checks.
- AF_XDP is an optional DIRECT-only accelerator. Proxy, DNS-conflict, unknown,
  malformed, fragmented, and established traffic stays on TC/kernel paths.

The new `rc4-global-audit.yml` workflow runs focused Smart/eBPF tests, race
tests, `go vet`, and Smart Zig Linux cross-builds. It does not compile on
macOS, mutate PVE, or deploy to 107/115.

The AF_XDP adapter uses one shared UMEM fill/completion ring and per-queue
RX/TX rings. A bounded frame ownership table prevents duplicate descriptors
across receive, transmit, completion, and recycle paths. The XDP control map
is enabled only after mode-specific attach, every XSK queue binding, and
generation/bank agreement. Any failed probe, link/queue change, or ring
backpressure returns to TC.

The RC4 Linux gate was rerun after the shared-ring lifecycle fix. Global audit
run `33318217594`, XDP engine run `33318217568`, and release build run
`33318296212` passed. The release matrix produced amd64/arm64 glibc and musl
artifacts with `publish_release=false`; no unreviewed release tag or production
deployment was created.

The latest adapter correction sizes the UMEM-wide fill/completion rings for the
bounded total frame budget and marks only queue 0 as their mmap owner. Closing
any multi-queue adapter therefore cannot unmap an alias twice or invalidate a
ring still being released by the owner. Empty frame data is also returned as
an explicit null pointer instead of indexing a zero-length slice.

Remaining acceptance is environmental, not an unguarded code path: a separate
multi-queue physical/virtio lab must demonstrate native/copy/offload attach,
bidirectional DIRECT forwarding, no fill starvation, link-change rollback,
and no proxy p95 regression before any production host is eligible. VM115 is
currently TC-only because its device probe reports no XDP program capability;
its two virtio queues alone are not sufficient.
