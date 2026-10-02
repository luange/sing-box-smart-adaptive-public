# Official-base strategy

## Policy
1. **Primary upstream** = SagerNet official tags only (not whole-tree reF1nd merges).
2. **Always keep ours** (first-party):
   - Smart, AdaptivePool, eBPF-ours, DirectOffload
   - Provider (remote/local/inline)
   - LoadBalance, Pass
   - Connection history (`with_connection_history`)
3. **Never port**: reF1nd cilium eBPF stack as a whole-tree overlay.

## Branch `adaptive/official-v1.14.0-smart-ebpf`
- Base: official SagerNet `v1.14.x` stable line (upstream tags are merged explicitly;
  inspect `git describe --tags` for the exact revision in a checkout)
- Version: `1.14.x` (project revision is recorded in the binary build metadata)
- Default tags include `with_ebpf` and `with_connection_history`

## Coherence model (must stay true)

```
route match
  └─ MatchInputs (per winning rule, incl. RuleSetItem.MatchClass)
        └─ verdict learn (IP-only) + NoteRoutedDirect (DIRECT leaf / sticky DIRECT)
DNS answer
  └─ DNSAnswerObserverHub → eBPF dns_prefill promote
dial success (ConnectionManager)
  └─ VerdictLearnerHub.MaybeLearn{TCP,UDP}
  └─ ConnectionSplicerHub.TrySpliceTCP (opt-in)
group dial leaf
  └─ NoteRealOutbound / AppendRealOutbound (shared Extended)
        └─ traffic tracker FinalizeChain on close → connection_history
multi eBPF inbound
  └─ hubs: DirectOffload / DNSAnswer / VerdictLearner / ConnectionSplicer
```

### Why hubs
Single-slot `MustRegister` cannot host multiple eBPF inbounds. Every cross-cutting
hook is a hub registered once in `box.New`, with each inbound `Add`/`Remove` on start/close.

### Why ConnectionManager hooks
### Learn metrics (ops)
After dial, `invoked` / `non_direct` must move under proxy traffic (proves CM→hub→coord).
`writes>0` only when empty DIRECT dials userspace (CN bulk is static bypass_rule_set).
Mixed shared-network is eligible; tun/socks are not.

Learn + splice only fire **after** a proven dial. Registering the learner without
wiring `route/conn.go` is a silent no-op (was a production gap).

### Why FinalizeChain
Tracker snapshots chain at route time via group `Now()`. Smart may dial another
leaf. Groups call `NoteRealOutbound`; on close, history rebuilds leaf → root.

### RuleSet MatchClass
Pure geoip (`ContainsIPCIDRRule` only) → `RouteMatchIP` (learn allowed).
Domain/process/wifi mixed sets OR non-IP bits → learn fail-closed.
Static `bypass_rule_set` still covers bulk CN without waiting for learn.

### AdaptivePool PreMatch
Intentionally `PreMatchDisabled` — unwrapping would skip observation/retry.
Smart/selector/urltest/loadbalance implement `PreMatchOutboundGroup`.

## Feature enable notes

### connection_history
```json
{
  "experimental": {
    "connection_history": {
      "enabled": true,
      "path": "/var/lib/sing-box/connection-history.db",
	  "detail_retention": "6h",
	  "aggregate_retention": "720h",
	  "segment_size": "8M",
	  "max_disk_size": "256M"
    },
    "clash_api": { "external_controller": "127.0.0.1:9090" }
  }
}
```
API: `GET /history` (status), `/history/summary|trend|connections|domains|...`

Closed records returned by `/history/connections` include a best-effort
`closeReason`. Clean client/remote EOF, reset, dial/handshake timeout, idle
timeout and unknown termination are kept distinct; `history.status` continues
to expose dropped open/close events separately.

The path is a compatibility anchor. SBH2 data lives in `<path>.segments`; a
legacy BoltDB at `<path>` is reported as `legacyDatabaseSize` but is never mmaped.
Expiry unlinks immutable segments, so deleted history immediately returns disk space.

### eBPF splice (proxy zero-copy)
Requires kernel sockmap. Config on eBPF inbound `outbound_offload.splice`.
Default on 115 keeps splice disabled for stability; path is fully wired when enabled.
(Baseline note: this branch has since moved to the official 1.14 stable line,
post-v1.14.9; current release is v1.14.15.)
(ConnectionManager → SplicerHub → inbound coordinator).

### loadbalance / pass / adaptive_pool
Registered outbound types. Production 115 uses smart groups; others are optional.

### provider duplicates
Duplicate node names get a **content-stable** suffix (` #` + 8 hex) so reloads do not
churn smart pins the way order-based ` (2)` did. Fallback remains ` (n)`.

## Build
```bash
./scripts/cross-build-official-smart-ebpf.sh
# or on vm112 with full tags + with_ebpf + with_connection_history
```

## Deploy checklist
1. Binary size >50MB
2. `sing-box version` prints `official-smart-ebpf`
3. `sing-box check -c config.json`
4. Log: `direct_offload=route+prefill+learn`
5. Restart twice with no `sing-box did not close!`
6. After DIRECT traffic: verdict metrics / learn skips move off zero when hooks engaged
7. `/history/connections` shows leaf tags under smart (not only group tag)
