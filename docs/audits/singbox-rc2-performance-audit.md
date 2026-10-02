# sing-box v1.14.0 性能与兼容性审查

## 范围

审查基线为官方 `v1.14.0`（`0b8995879f29a9b98ee027bc17b75e101445b238`）；历史记录中
保留了 rc4/rc5 阶段的验证证据。
自有分支在保留 Smart、Zig policy、eBPF v3、
provider、connection-history、Clash/Zashboard API 和 PBR 适配层。没有把代理协议
栈重复改写成第二套实现。

## 上游改动核对

rc2 的 QUIC 拥塞控制、FakeIP UDP 回程映射、异步 DNS/本地缓存分区、DNS TCP
连接复用、UDP 批处理、URLTest 阻塞修复、DNS 乐观缓存和 tproxy UDP 回写缓存均
已在合并树中；自有扩展只在相应边界补充观察、画像和卸载逻辑。

## 已整改的瓶颈

1. **Smart 选路锁竞争**：`rankPooled` 原来对每个候选重复读取
   `candidateProbeKey`，一轮最多三次读锁。现在在同一个候选快照边界复制一次
   identity 表，后续画像、死探测和 Zig 选择均复用快照；语义不变，减少大组
   的锁往返。
2. **DNS prefill goroutine 放大**：每个 DNS 答案原来直接创建 goroutine，突发
   查询会把堆和调度器放大。现在采用两个有界 worker slot，满载时丢弃 advisory
   hint（fail-open），关闭时等待已接纳任务完成，并记录
   `dns_prefill_queue_drops`。
3. **发布漂移**：Linux 发布工作流已改为匹配 rc4 gateway 标签，避免 rc4 核心
   推送后不触发精简 eBPF 构建。
4. **已建立连接卡住**：Smart 在每个真实请求写入后启动一个有界响应计时器，
   即使连接已经收到过首字节也继续观察后续请求；响应或关闭会取消当前计时，
   `established_stall_timeout`（默认 10s，5s–2m）内无响应才记一次失败并唤醒
   共享探测，不主动制造流量，空闲长连接不会被惩罚。
5. **Smart 状态混淆**：Clash 扩展新增最多 32 个独立
   `network/site/transport` 上下文快照，旧的顶层字段仍保留为兼容视图。
6. **VMess WebSocket 崩溃**：修复失败升级返回 typed-nil `*WebsocketConn`
   导致清理路径空指针 panic，并避免并发健康检查修改共享 Header；异常网络
   分支也会关闭已建立连接。

### 107 transparent-huge-page regression (2026-08-30)

The RC4.1 process on VM 107 had only about 30 MiB of live memory at the
Clash `/memory` endpoint, but RSS had climbed to 260 MiB. `/proc/$pid/smaps`
showed a 181 MiB anonymous heap region backed by about 158 MiB of
`AnonHugePages`; the process had only 34 TCP and 9 UDP sockets. This was
retained transparent huge-page backing, not a DNS/session leak. The OpenRC
service now exports `GODEBUG=disablethp=1` (and the systemd unit does the same)
so released arenas can return to the kernel. After an atomic restart the same
binary stayed on version `1.14.0-rc.4-official-smart-ebpf-v3.45.1-stall-context`;
RSS was 73 MiB immediately and 82 MiB after 65 seconds, `AnonHugePages` was
4–8 MiB, both 9090/9091 remained listening, and Google/YouTube returned 204.

## 验证门

本分支不在 macOS 编译。提交 `0ef5c910` 已通过 Smart/Zig/C ABI CI 及
amd64/arm64 glibc/musl Linux 构建；提交 `ef21d5e4` 追加了 WebSocket typed-nil
回归测试。107 已在生产以 `0ef5c910` 产物运行，启动、9091 API、Google/YouTube
204 和 65 秒稳定性观察均通过，未出现新的 panic。eBPF 仍由内核 fast path
负责，代理节点流量不会错误套用 DNS prefill 的直连判定。

### RC4 fifth-round global audit (2026-08-30)

The fifth scheduled review rechecked Smart/Zig selection, eBPF v3 and the
XDP policy boundary, DNS prefill, connection-history retention, provider and
Clash API snapshots, and shutdown paths. No additional production defect was
confirmed. The one unsafe configuration path was fixed in `8855b7f4`: v3 now
rejects `xdp.enabled=true` until the Linux AF_XDP host adapter (UMEM, poll,
and bidirectional forwarding) is wired, instead of accepting a no-op setting.
The migration regression test and a Linux CI job were added in `4c43c3d8`.

Evidence: XDP workflow `33311048912` passed Go migration tests, Zig unit and
cross-build tests, BPF syntax/section checks, and policy-boundary checks. No
AF_XDP was mounted or deployed to VM 107/115; the existing TC/eBPF v3 path is
unchanged. The earlier Build workflow `33310899896` was intentionally not
used as a release gate because its desktop version-update step requires a
version commit and failed before compilation; it does not indicate a source
compile failure. Rollback point: `6d5796fe`.

### UDP failure-observation correction (2026-09-02)

Live NAS checks showed that TCP control probes can succeed while a real
UDP/QUIC flow remains half-open. The previous observer only reported that
condition when the caller closed its socket, so Smart could retain a broken
candidate indefinitely. UDP observation now arms a bounded watchdog on the
first successful write for response-oriented destinations (DNS, QUIC and
STUN), cancels it on the first response, and reports a classified write error
immediately. One-way UDP is still ignored and every flow reports at most one
failure. The timeout reuses `established_stall_timeout` (default 10s, bounded
5s–2m), so this is passive data-plane evidence rather than an extra business
probe. Regression coverage includes an in-flight blackhole and exactly-once
notification check.

### Smart primary/backup semantics (2026-09-03)

Smart combines URLTest evidence with a bounded primary/backup selector; it is
not a latency-only race and it does not continuously round-robin healthy
nodes. The process-wide probe registry shares URLTest cadence, cached results,
and endpoint single-flight admission across Smart groups. Each Smart group
still owns its business score, breaker, and service/site context so group
boundaries remain authoritative; this is deliberately not a claim that every
group has one mutable global score. Ranking first applies the health tier
(`healthy` → `warming`/`unknown` → `suspect` → `half_open` → `open`), then a
confidence-adjusted score using reliability, connect/first-byte tails,
throughput, jitter and retransmit evidence. The first eligible candidate is
the primary and subsequent eligible candidates are ordered backups; open
candidates remain standby until recovery confirmation.

Normal operation retains the primary through the switch margin, confirmation
window and cooldown. A hard dial or established-flow failure bypasses those
performance guards and promotes the next backup for that request; a bounded
hedge is only used during cold/uncertain startup or after the primary has
exceeded its response budget. A successful hedge is recorded as a raced
request, not as a node failure. The status API exposes `role=primary`,
`role=backup`, or `role=standby` so a displayed ranking change cannot be
mistaken for an actual failover. If every candidate is circuit-open, Smart
rotates a capped two-second half-open sample (single-flight per endpoint) using
the connectivity URLTest path for TCP and the independent DNS reachability
probe for UDP. Any success is immediately fed back into the profile and the
normal ranking; failures keep the recovery ladder (30s, 1m, 5m) and the
10-second per-group recovery gate. Suspect but still usable candidates are not
preemptively probed or replaced: the real dial/first-byte result is the
authoritative trigger for fast failover.

### Follow-up hardening (2026-09-03)

The process-wide probe registry now marks whether a caller received a fresh
network result. Cached answers remain available for the caller but no longer
reset a group breaker, inflate sample counts, or suppress a later real failure.
TCP, UDP, and recovery tracks also share an endpoint-scoped single-flight lock;
forced recovery re-enters the same admission path so it cannot race a second
track between two cache entries. The Zig policy kernel applies the same hard
health ordering as the Go host (`healthy` before `warming`/`unknown`, then
`suspect`, with `open` excluded) before comparing latency or throughput. These
changes are covered by freshness, cross-track, recovery-lock, and Zig policy
regression tests.

The ABI keeps the historical values (`state=3` suspect and `state=4` open) and
adds `state=5` for half-open recovery trials. This is additive so older C/FFI
consumers retain their existing meaning. Smart transport keys now preserve an
explicit IPv4/IPv6 suffix when the caller or destination provides one; generic
dual-stack destinations retain the legacy aggregate key until a concrete family
is known. TCP/DNS probes remain bounded and endpoint-single-flight. Data UDP and
QUIC continue to use passive response/write-failure evidence only: there is no
safe universal synthetic payload for arbitrary proxy protocols, so the data
plane is not falsely declared healthy by a DNS probe.

### Surge design cross-check (2026-09-03)

The attached Surge analysis was compared against the implementation rather than
copied verbatim. Its useful properties are now covered as follows: service
history is keyed by registered domain and transport, a successful connection
clears a local failure stain, and score selection remains primary/backup rather
than latency-only. Large catalogs additionally keep a bounded, two-hour
decaying use score; budgeted background cycles first deduplicate aliases by
canonical endpoint, probe the most-used half, and fill the remainder with the
stalest endpoints. The score is decayed both when written and when read, so an
old burst of traffic cannot remain artificially popular. Only successful TCP
selections contribute to this score; UDP keeps an independent health ledger.
This supplements the existing activity-aware rotation without adding a
user-facing knob or making use count override health.

The UDP no-response rule follows the safer part of the reference design: DNS
transactions can fail after one unanswered datagram, while QUIC/STUN wait for
three writes before arming the watchdog. A single lost handshake packet thus
cannot trigger a failover. Family-aware TCP and DNS probes use distinct shared
registry keys and the same endpoint lock. No synthetic data-UDP/QUIC payload is
introduced; arbitrary proxy protocols do not share a portable application-level
health request, so real response/write failures remain the authoritative data
evidence.

### Surge-compatible selection modes (2026-09-03)

The public Smart option `selection_mode` now exposes the deliberate policy
choice that was previously implicit. `primary_backup` (the default) preserves
health-tier ordering, confirmation, cooldown and hard-failure failover.
`balanced` uses stable rendezvous hashing over each network/site/transport
context, restricted to the best health tier and configured score margin. This
provides Surge-like same-tier dispersion without per-connection randomness or
keep-alive churn; an incumbent remains selected while it stays inside the
pool. The `random` value is accepted only as a backwards-readable alias for
`balanced`. Balanced mode remains host-side only in builds without `smart_zig`;
a Zig production build rejects it instead of creating a second decision path.

### Portrait freshness correction (2026-09-03)

The audit of field consumers found that reliability/sample counters were
half-life decayed, while the associated connect, first-byte, throughput,
jitter and retransmit values retained their old EWMA indefinitely. A quiet
endpoint could therefore keep stale latency evidence in the ranking after its
confidence had effectively vanished. Commit `a2f35d94` clears each evidence
class when its effective sample count falls below 0.25, while retaining the
success/failure counts as the neutral Bayesian prior. The new regression test
covers all four evidence classes and the normal short-interval EWMA test still
passes.

### Portrait consumer audit (2026-09-03)

Every stored field is now accounted for in one of three deliberate paths:

| Evidence | Decision consumer | Non-decision consumer |
| --- | --- | --- |
| successes/failures | Bayesian reliability, confidence cost, health tier and breaker | persistence |
| connect/first-byte EWMA and tail | score, absolute switch floor and Zig candidate snapshot | status API fallback |
| connect/first-byte sample counts | EWMA update, freshness decay and evidence-presence gate | persistence |
| throughput and sample count | bulk-profile detection, advisory passive floor and bulk score | status/persistence |
| jitter | interactive/UDP score and Zig candidate snapshot | persistence |
| retransmit ratio and sample count | bounded TCP score penalty; penalty ramps with 1/3/≥3 effective samples | status/persistence |
| circuit and last-updated timestamps | eligibility, recovery, decay and pruning | persistence |

`smartEstimate.LastUpdated` and the unused `smartScore` wrapper were removed;
neither had a consumer. A single TCP_INFO close sample no longer receives the
full retransmit penalty, so one transient observation cannot trigger a
performance switch. The raw means and per-class counters remain because they
are needed for API diagnostics, EWMA maintenance, or freshness gates; they are
not silently treated as extra score dimensions. The Go exploration denominator
now includes only eligible candidates in the best health tier, matching the
Zig kernel instead of letting open/lower-tier history influence ranking.

### Zig-only production policy (2026-09-03)

The release profile now treats `smart_zig` as the sole Smart decision kernel.
If the Zig library or ABI is missing/incompatible, Smart construction fails
instead of silently re-entering the Go policy path. A runtime engine allocation
failure also fails closed for that ranking rather than selecting through a
second policy owner. The untagged Go path remains available only for
upstream-compatible development and cgo-less platforms.

This does not move socket I/O into Zig: sing-box still owns protocol dialing,
TCP/UDP probes and connection lifetimes, while Zig receives bounded evidence
and returns the policy decision. `selection_mode=balanced` now uses the same
versioned Zig ABI as `primary_backup`; silently using a second Go selector is
still forbidden.

The same audit also found that two provider aliases could join one shared
probe but both increment the local portrait as if they were fresh network
samples. TCP/UDP probe-cycle accounting now coalesces observations, success
counters and failure penalties by EndpointProfile, so aliases cannot inflate
confidence or accelerate phase transitions. UDP probe candidates are
deduplicated before the bounded budget is applied.

### Lifecycle and ABI hardening (2026-09-03)

The follow-up review found two boundary cases that were not visible in the
steady-state path. A provider callback copied before shutdown could pass the
initial `closing` check and repopulate a catalog after `Smart.Close` had cleared
it. Provider-map access is now locked, and catalog rebuilds re-check the close
flag before and after taking the catalog lock; a late callback therefore cannot
resurrect a retired group. DNS FakeIP callbacks now share the same bounded
admission and `WaitGroup` barrier as real-DNS prefill work, so the eBPF shared
network cannot be cleared while a hint is being published. FakeIP-only setups
also register without requiring a Router or OutboundManager, while real-DNS
prefill still fails open when either dependency is absent.

The Zig C ABI now treats non-finite values and negative counters/latencies,
throughput or weights as unknown/neutral; reliability remains bounded to
`[0,1]`, and positive infinity is a worst cost where appropriate. This keeps
EWMA state, confidence costs, throughput mode detection and ordering
comparisons finite and transitive. Regression tests cover invalid latency,
sample counts, delay and configuration values. Local validation for this pass
was limited to `gofmt` and `git diff --check`; Linux Zig/Go/eBPF builds remain
CI-only because eBPF cannot be validated by a macOS toolchain.

### Zig parameter parity and concurrent-result hardening (2026-09-04)

The strict option-to-ABI review found two real omissions. `site_stickiness`
was accepted by Smart but never reached the Zig policy state, and
`switch_min_improvement` was enforced only by the non-Zig reference path. ABI
version 4 appended both millisecond fields; the current ABI version 5 also
carries the host-configured `min_samples` confidence floor. `smart_engine_set_selected`
receives the completion timestamp and starts stickiness only after a real dial
succeeds. Zig also matches the host's p95 latency order, half-open penalty,
jitter presence rule, and exploration denominator. Hard-open and provider
removal failover still bypass the performance floor.

The same review found that concurrent dial completions could let an older
healthy result overwrite a newer incumbent in the Zig path. Each pooled ranking
now records the selected tag and timestamp generation; `markSelected` rejects
only stale healthy results while allowing failure-driven failover. The snapshot
fields are cleared on pool release to avoid retaining provider strings. Zig
unit, C ABI smoke, and Smart integration tests cover stickiness, absolute
latency gating, and stale-result rejection; Linux CI remains the build gate.
