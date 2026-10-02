# AF_XDP host-adapter implementation audit (2026-08-30)

## Delivered

- `xdp-engine/src/linux_adapter.zig` implements bounded Linux AF_XDP
  UMEM, one XSK per selected queue, RX/TX/fill/completion rings, poll,
  completion recycling, borrowed frame access, and explicit copy/zero-copy
  bind modes. The fill/completion rings are created once per shared UMEM (not
  once per queue), and a bounded frame ownership table prevents duplicate
  recycle/TX descriptors when a frame moves between queues.
- `xdp-engine/src/controller.zig` enforces the hand-off order: probe → verified
  program attach → every queue bound → XSKMAP publication → control enable.
- `common/ebpf/native/xdp_runtime.c` rejects control enable until all selected
  XSKMAP slots are present, clears slots on detach, and rejects the current
  unsupported scatter-gather mode.
- The XDP program and probe matrix now keep RX scatter-gather on TC until a
  bounded segment walker exists.
- The shared UMEM fill/completion mmap is owned and released exactly once;
  its ring capacity covers the bounded aggregate frame budget instead of only
  one queue's RX/TX ring.

## Verification

GitHub Actions run `33316181921` passed all jobs: Zig tests, Linux
x86_64/aarch64 cross-builds, C ABI smoke check, Go migration tests, BPF syntax,
sections, provenance, and policy-boundary scans. No macOS compilation was
used.

The RC4 follow-up gates also passed: global audit `33318217594`, XDP engine
`33318217568`, and Linux release matrix `33318296212` (amd64/arm64, glibc/musl,
release publication disabled).

## 115 boundary

The guest currently reports Debian cloud kernel `6.12.100+deb13-cloud-amd64`,
`virtio_net`, two RX/TX queues on `eth0` and `eth1`, and kernel-wide XDP/XSKMAP
support. The device probe reports no XDP program type and `bpftool net` shows
no XDP attachment; only TC `sb_share_in` is active. Therefore 115 is not an
AF_XDP production target yet. Virtio queue count alone is insufficient: a
privileged mode-specific attach, all-queue bind, and bidirectional DIRECT
forwarding test are still required. TC remains the live path.

### 115/PVE capability recheck (2026-08-30)

The apparent contradiction is a layer distinction, not a stale queue setting:

- The guest kernel already has `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`,
  `CONFIG_XDP_SOCKETS=y`, `CONFIG_NET_CLS_BPF=m`, and `CONFIG_NET_ACT_BPF=m`;
  `bpftool feature probe kernel` reports the XDP program and XSK map types as
  available.
- `qm config 115` and the live tap devices both show `virtio` with
  `queues=2`; `virtio_net.ko` contains the XDP receive/transmit paths.
- The device-scoped probe still reports `xdp` and `sched_cls` as unavailable,
  so no attach admission is inferred from the global kernel result.
- The PVE host presents the guest through bridges backed by its single
  physical `tg3` interface (`ens9`); that driver exposes no XDP feature. PCI
  passthrough of it would remove the host uplink and is not an acceptable
  production change.

Therefore recompiling the guest with the same config would not fix the
observed device probe. Generic/SKB XDP may still be evaluated in an isolated
clone after a no-op attach test (and any required virtio offload constraints),
but native zero-copy and hardware offload require a separately supported NIC or
SR-IOV/VF. Until that test exists, the safe production choice is TC v3.

### Subtraction audit (2026-08-31)

The XDP surface was checked for duplicate or unreachable runtime paths. The C
loader functions are all consumed by the public ABI or by close/rollback paths;
the Zig `Session` (adapter lifetime) and `Controller` (kernel hand-off gate)
hold different state and are both exported, so deleting either would remove a
cross-core integration contract. No safe runtime deletion was found. The only
confirmed cleanup in this audit is the Smart-side duplicate metadata state;
XDP behavior and its TC fallback remain unchanged.

## Rollback

Do not publish the XDP control record. Leaving `xdp.enabled=false` keeps the
existing v3 TC path unchanged. If a lab attach fails, close the adapter and
detach the program; the C runtime clears XSKMAP entries before returning to TC.
