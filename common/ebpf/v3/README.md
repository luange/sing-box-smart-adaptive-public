# eBPF data plane v3

Independent TC + `socket_assign` data plane with a Go control plane.

Design: `Documents/Codex/2026-07-17/new-chat-3/outputs/EBPF-DATAPLANE-V3-DESIGN-FOR-GROK.md`

## Layout

| Path | Role |
|------|------|
| `kern/abi.h` / `abi.go` | Shared verdict ABI (generation, source, reason, expiry) |
| `kern/parser.h` | Bounded L2/L3/L4 parse (including the L4 payload offset used by DNS observation) |
| `kern/policy_maps.h` | Double-bank LPM, flow, DNS hint, bounded DNS observation queue, SOCKMAP, stats |
| `kern/tc.bpf.c` | TC ingress decision order + minimal egress |
| `decision.go` | Pure model of §5 order (unit-tested without kernel) |
| `compiler.go` | Static sink eligibility (§7.2) |
| `publisher.go` | Double-buffer publish + exact-flow pairs |
| `dns_hint.go` | CDN conflict isolation (§8) |
| `generation.go` | Atomic bank + generation flip |

The v3 telemetry map is a `PERCPU_ARRAY` with one value containing all 32
counters. Kernel actions update the CPU-local vector without atomic RMW or a
second lookup for byte accounting; the Go backend aggregates all possible CPU
slots when exporting metrics. Policy maps remain shared so routing decisions
are consistent across CPUs.

Control-plane wiring: `protocol/ebpf/v3` (`Lifecycle` + `DataplaneSink`).
Kernel sink: `common/ebpf.V3Backend` (sole writer of TC maps).

### Single publisher (do not dual-brain)

| Userspace event | Kernel write |
|-----------------|--------------|
| bypass / static snapshot | `PublishStaticDirect` (inactive bank + gen commit; deletes removed keys) |
| dns_prefill / route promote | `PublishDNSHint` + `MergeDynamicDirect` (separate expiring LPM, **no** gen bump) |
| plaintext DNS replies | bounded TC `v3_dns_observe` LRU → userspace domain-rule evaluation → the same hint/promote path |
| bare-DIRECT learn | `PutDirectFlow` (fwd+rev, `direction=0`, swapped 5-tuple) |
| learn failure | `DeleteDirectFlow` |
| iface / policy reload | one static republish (generation bump invalidates flow/DNS) |

## Config (opt-in)

```json
{
  "type": "ebpf",
  "capture_local": false,
  "shared_network": {
    "enabled": true,
    "engine": "v3",
    "include_interface": ["br-lan"],
    "data_plane": "socket_assign",
    "policy_offload": {
      "enabled": true,
      "static_rules": true,
      "exact_flow_learning": true,
      "dns_ip_hint": "safe",
      "fakeip": true
    },
    "failure_mode": "proxy",
    "drop_udp_443": false
  }
}
```

- Empty `engine` → **v2** (unchanged).
- `engine: v3` is required for this path.
- Map miss / IP fragment / DNS conflict → **proxy (NEED_USERSPACE)**, never silent DIRECT. A truncated or non-IP frame with no trustworthy tuple is passed to the kernel without a mark because socket assignment cannot be performed safely.
- UDP/443 is **not** dropped unless `drop_udp_443: true`.
- With `shared_network.enabled`, **`capture_local` defaults to false** (PA/PBR gateway). Explicit `true` still allowed for host capture.
- When `policy_offload.enabled` and `dns_ip_hint` are enabled, TC may observe UDP replies from source port 53. The observation is advisory only; malformed/long names are discarded and no packet verdict is changed in the kernel.
- A maximum of 4096 LRU observations is retained and the userspace monitor drains at most 128 rows every three seconds. Queue pressure therefore cannot create an unbounded goroutine or heap burst; dropped/evicted observations fail open and are not treated as routing failures.
- `dns_ip_hint: off` keeps the plaintext sniffer disabled, even when `fakeip` is enabled. FakeIP answers use their separate authoritative observer path.
- Learned DIRECT promotions never enter the double-bank static snapshot. They use bounded, generation-checked dynamic LPM maps with an answer-derived TTL; expired rows are reclaimed before capacity is reported, and static proxy/block rules plus more-specific exact-flow verdicts always win.

## Build BPF object (Linux only)

```sh
make -C common/ebpf generate   # produces v3/kern/tc.bpf.o
make -C common/ebpf check
```

Do not generate on macOS. Kernel load/attach and 117 canary remain Linux lab work.

## Tests (any OS)

```sh
go test ./common/ebpf/v3 ./protocol/ebpf/v3
```

## Hard constraints

1. No dae source copy — architecture only.
2. No first-packet domain magic.
3. DNS weak hints never first-packet DIRECT.
4. No default QUIC drop.
5. eBPF does not run Smart node selection.
6. No AF_XDP in production path.
7. Reload never mutates the active policy bank in place.
8. Deploy **117** before **115**.
