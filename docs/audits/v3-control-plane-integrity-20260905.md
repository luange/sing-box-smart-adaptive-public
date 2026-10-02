# v3 control-plane integrity audit (2026-09-05)

## Findings

Three review items were checked against the current `official-v1.14.0-smart-ebpf`
tree.

1. **v3 prepare fallback:** confirmed. `sharedNetwork.Start` kept the v3
   lifecycle after a kernel prepare failure, while `learnV3Flow` and
   `revokeExactFlow` selected it solely by pointer presence. A v2 fallback
   could therefore learn into an unbound memory model and fail to remove the
   tuple from the live v2 map.
2. **Static snapshot mirroring:** confirmed. The parent published directly to
   the kernel backend and only copied the generation into the v3 model; the
   model's policy bank remained empty/stale.
3. **DNS/source identity:** confirmed as an API boundary. The observer carries
   domain, addresses, and FakeIP provenance, but no client/source/VLAN identity.
   A global DIRECT promotion is unsafe while `mac_source_policy` is enabled.

The optional AF_XDP engine is already explicitly experimental: configuration
with `xdp.enabled` is rejected until the Linux host adapter has a privileged,
multi-queue integration path. No production XDP call site or VM deployment is
claimed.

## Remediation

- v2/v3 selection now follows the authoritative `engineV3` flag for both learn
  and revoke, with a regression test covering a stale lifecycle on v2 fallback.
  The v2 backend now deletes the exact flow key instead of treating revoke as
  a no-op, so a failed learned flow cannot remain eligible until generation
  rollover.
- `Lifecycle.PublishStaticDirect` atomically mirrors a normalized, de-duplicated
  snapshot to the kernel sink and memory bank. Parent refreshes use this API;
  generation and active policy contents are tested together.
- DNS/FakeIP promotion is fail-open but disabled when `mac_source_policy` is
  enabled. A warning is emitted once at wiring time; DNS resolution itself is
  not blocked. A source-aware observer is required before re-enabling global
  promotion for that policy mode.

## Verification

Portable v3 tests cover the memory snapshot and generation invariants. Linux
`with_ebpf` tests must run in CI because the protocol package is Linux-only and
the live sink requires cgo/eBPF support. No production VM or configuration was
modified by this audit.
