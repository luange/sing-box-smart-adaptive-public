# eBPF v3 MAC snapshot recovery audit

## Findings addressed

The v3 source-MAC map is a single hash map, so a replacement can observe a
transient mixed state while individual syscalls execute. The publisher already
restores the previous snapshot on failure; this audit closes the remaining
failure policy:

1. A failed replacement first enters a MAC-only quarantine and clears
   `FlagMACSource` in the live control record. This keeps uncertain rows inert
   without retiring unrelated static, flow, or DNS state.
2. If that control write fails, the lifecycle escalates to the shared
   generation fuse. If generation invalidation also fails, it disables the
   complete v3 dataplane. Every escalation is returned as a joined error.
3. While quarantined, later control refreshes cannot re-enable MAC lookup. A
   successful complete replacement clears the quarantine and permits normal
   re-enable without restart.
4. Capacity is checked after zero-key filtering and duplicate-key
   normalization, matching the single kernel map's actual slot usage.
5. Generation invalidation retires dynamic DIRECT and source-MAC model rows as
   well as flow/DNS evidence, so diagnostics cannot report rows that TC will
   reject by generation.

## Verification

`go test ./common/ebpf/v3 ./protocol/ebpf/v3 ./common/ebpf/... ./protocol/ebpf/...`,
`go test -race ./common/ebpf/v3 ./protocol/ebpf/v3`, and `go vet` pass. Tests
cover local MAC quarantine, control-write escalation, whole-dataplane fuse,
duplicate-key capacity, and generation retirement. No production dataplane was
changed by this audit.
