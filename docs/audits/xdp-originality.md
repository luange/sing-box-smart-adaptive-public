# XDP originality and provenance audit

## Scope

This audit covers `common/ebpf/v3/kern/xdp.bpf.c`,
`common/ebpf/v3/kern/xdp_policy_maps.h`,
`common/ebpf/native/xdp_runtime.c`, and the Zig code under `xdp-engine/`.

The implementation is first-party code written for this repository. It does
not copy, vendor, or splice source from dae, landspace, libbpf, libxdp, Aya,
Mihomo, or another proxy project. Linux UAPI names, constants, and structure
layouts are used as interfaces; those are not implementation code. The BPF
program uses the repository-owned v3 parser and policy ABI.

## Boundary checks

- Kernel code has GPL-3.0-or-later headers and uses only bounded verifier-safe
  loops and map accesses.
- Userspace policy and ownership logic is in Zig; no Go package implements the
  XDP policy or ring state machine.
- `Makefile` embeds a SHA-256 provenance string in the object. `xdp-check` and
  `check-xdp-source` reject a stale generated object in Linux CI.
- The CI boundary scan rejects socket-assignment or TC-mark symbols in the XDP
  source. Proxy/unseen traffic is structurally `XDP_PASS`.

## Review rule

Future imports must be rejected unless they are (1) Linux UAPI definitions,
(2) a separately reviewed dependency with a compatible license, or (3) a
design reference with no source reuse. Any borrowed algorithm must be recorded
here with its license, link, and a clean-room adaptation note before merge.
