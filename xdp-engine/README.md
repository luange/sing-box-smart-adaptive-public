# Next-gen XDP policy core

Host-neutral Zig module for the optional AF_XDP DIRECT fast path.  The Linux
host adapter is now implemented in `src/linux_adapter.zig` and exported as a
small C ABI in `include/xdp_engine.h`; non-Linux builds select an explicit
unsupported-platform stub.

Design: `docs/design/next-gen-xdp.md`.

This directory classifies packets, evaluates NIC capability samples, selects
hardware/native/generic XDP mode only after a real program probe, and tracks
attach/fallback state. `afxdp.zig` owns bounded ring arithmetic;
`linux_adapter.zig` owns Linux AF_XDP socket/UMEM/ring/poll/ownership
operations. `controller.zig` is the host-neutral ordering gate shared by a
sing-box or mihomo integration. Proxy traffic is never mapped to
`XDP_REDIRECT`.

The adapter uses one shared UMEM fill/completion ring for all queues and
separate RX/TX rings per XSK. The shared rings are sized for the total bounded
frame budget (up to the configured ring limit), while RX/TX rings remain
per-queue. Frame addresses are therefore not queue-owned:
the bounded ownership table (`in_kernel` → `rx_owned` → `tx_owned`) is the
source of truth and every recycle returns to the shared fill ring. This avoids
duplicate descriptors and the cross-queue frame rejection that can otherwise
starve a multi-queue XSK setup.

The adapter does not attach or enable the XDP policy by itself. A host must
first verify the program/mode, open and bind every queue, publish every XSK
FD to the XSKMAP, and only then enable the separate XDP control record. Any
failure keeps TC as the live path. The sing-box option therefore remains
gated until a host integration supplies those ordering guarantees.

Mode selection is conservative:

- `auto`: verified hardware offload → verified native/zero-copy → verified
  generic/SKB; otherwise TC.
- `skb`, `native`, `offload`: explicit mode, no silent downgrade.
- Every empty XSK slot, ring-starvation event, verifier failure, link change,
  or queue mismatch returns traffic to TC/kernel forwarding.

The kernel object is `common/ebpf/v3/kern/xdp.bpf.c`; its mode-aware loader is
the Linux-only `common/ebpf/native/xdp_runtime.c`. There is no userspace TCP/
UDP stack: "outbound" means a DIRECT frame is transmitted by the adapter's
paired TX ring after it has been classified by the ingress program. Proxy and
uncertain traffic stay in the kernel/TC path.

The host must serialize `Session` methods. The core holds no locks and no
global mutable session.

## Host integration order

The exported ABI is intentionally usable by either sing-box or mihomo without
sharing their control plane:

```c
/* mode 0 is zero-copy; mode 1 is an explicit copy-mode opt-in */
struct sb_xdp_adapter_config cfg = {
    .ifindex = ifindex, .queue_count = rx_queues,
    .ring_size = 2048, .frame_size = 2048, .frame_count = 4096,
    .mode = 0,
};
if (sb_xdp_adapter_probe_bind(&cfg) == 1 &&
    sb_ebpf_xdp_probe_mode(&runtime, ifindex, SB_EBPF_XDP_MODE_NATIVE) == 0) {
    struct sb_xdp_adapter *a = sb_xdp_adapter_open(&cfg);
    for (uint32_t q = 0; q < rx_queues; q++)
        sb_ebpf_xdp_set_xsk(&runtime, q, sb_xdp_adapter_queue_fd(a, q));
    /* Fails with EAGAIN until every queue has an XSKMAP entry. */
    sb_ebpf_xdp_set_control(&runtime, true, generation, bank,
                            rx_queues, 2048, false, now_ns);
}
```

The packet loop must call `sb_xdp_adapter_poll`, classify only DIRECT frames,
queue them to a TX ring, and recycle every frame on TX completion or any
backpressure error. On link/queue/MTU change it disables the control record,
detaches XDP, clears the XSKMAP, and returns to TC before re-probing. No
failure in this sequence is allowed to stop the inbound or remove TC.

## Build (Linux CI / PVE only)

Do not compile on macOS. Do not deploy to hosts 107 or 115.

```sh
zig build test -Dcpu=baseline
zig build -Dcpu=baseline -Doptimize=ReleaseFast
# Linux-only cross builds (run in CI, not on macOS)
zig build -Dtarget=x86_64-linux-gnu -Dcpu=baseline -Doptimize=ReleaseFast
zig build -Dtarget=aarch64-linux-gnu -Dcpu=baseline -Doptimize=ReleaseFast
```

Zig 0.14, portable `baseline` CPU, same convention as `smart-engine/`.
