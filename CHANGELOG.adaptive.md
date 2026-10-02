# Changelog（adaptive 增量）

只记录相对 **SagerNet 官方 tag** 的本仓库变更。上游 changelog 见 `docs/changelog.md`。

## Unreleased — provider protocol capability filtering

- Parse Sing-box JSON, Clash YAML, SIP-008 and raw URI subscriptions member by
  member; malformed, unknown, schema-only and unsupported protocols are skipped
  without discarding valid members.
- Emit bounded, redacted provider diagnostics with provider/index/tag/type and a
  reason code; subscription URLs, query strings and credentials are never logged.
- Apply the same capability gate at every public parser boundary and reject an
  all-invalid subscription with `no supported servers found`.
- Guard raw URI parsing from legacy panic paths so a malformed line cannot abort a
  provider refresh.
- Bound warning de-duplication so long-running provider refreshes cannot retain
  unbounded diagnostic keys.
- Register the runtime protocol-capability views in the normal box context;
  minimal builds now enforce the same supported-protocol filter when providers
  are parsed through the production lifecycle, not only in direct parser tests.

## Unreleased — eBPF v3 MAC snapshot safety

- Count unique normalized MAC keys for capacity preflight; duplicate provider or
  rule entries no longer consume phantom map slots or trigger false rejection.
- Keep uncertain one-map MAC publications behind a subsystem-local quarantine:
  a failed update disables only MAC lookup first, preserving healthy flow/DNS
  and static generations. A failed control write escalates to generation
  invalidation, then to a whole-dataplane disable as the final fail-closed
  fuse.
- Retire dynamic DIRECT and source-MAC model rows whenever the shared kernel
  generation changes, preventing diagnostics from reporting rows that TC will
  ignore. Successful MAC replacement clears the quarantine without restart.
- Add failure-path, escalation, duplicate-key, and generation-retirement tests.

## Unreleased — connection close diagnostics

- Record a bounded, race-safe `closeReason` for routed TCP/UDP history entries.
- Distinguish clean client/remote EOF, reset, dial/handshake timeout and idle
  timeout without changing routing or connection lifetime semantics.
- Preserve existing history queue-drop counters; no sensitive payload or URL is
  recorded.

## Unreleased — explicit Smart selection modes

- Expose two numeric `mode` values: `1` for stable same-tier dispersion and `0`
  for fixed-primary behavior.
- Make mode `1` the default, using A/B/C ordering and same-tier dispersion;
  retain immediate hard-failure failover and the PBR group boundary.
- Keep mode `0` as the explicit stable-primary mode, with failure-only takeover.
- Continue accepting the legacy string `selection_mode` for existing configs.
- Report the active selection mode in Smart status so operators can verify the
  configured policy at runtime.

## Unreleased — Zig Smart production backend

### Explicit numeric Smart modes in Zig ABI

- Keep numeric `mode` values 0/1 in the versioned Zig policy ABI, defaulting to 1.
- Keep health tiers, score margin, incumbent retention, confirmation and
  immediate hard-failure failover in one policy kernel; no second Go selector
  is used.
- Add a context seed to the ABI and a deterministic rendezvous hash so
  independent network/site/transport contexts spread without per-connection
  churn.

### Score evolution (v3.42)

- Add bounded tail-EWMA latency portraits exposed as `connect_p95_ms` and
  `first_byte_p95_ms`; a single slow sample remains visible without retaining
  an unbounded per-node history.
- Align Go and Zig scoring: interactive traffic now emphasizes reliability,
  p95 first-byte and p95 connect latency, with a small confidence term; bulk
  and UDP keep separate weights.
- Apply hard-open eligibility before node weights, preventing a high weight
  from resurrecting a failed endpoint.
- Share Go-side dial, first-byte and throughput observations by canonical
  Endpoint identity, so duplicate subscription lines use one portrait.
- Add `switch_min_improvement` (default `100ms`) as an absolute p95 latency
  floor in addition to the relative switch margin.

- Connect the bounded Zig policy kernel to production `protocol/group/Smart`
  behind the `smart_zig` build tag; release Linux binaries now run Zig for
  scoring, confirmation, and cooldown instead of executing two state machines.
- Feed TCP/UDP dial and flow observations into Zig using canonical endpoint
  identities, so duplicate provider display names share policy evidence.
- Keep manual pin, provider refresh, EndpointProfile/status, failure wakeups,
  and switch audit ownership in the Go host with a safe Go fallback for ABI or
  allocation failure.
- Add Linux CI compile coverage for the production adapter and build the Zig
  static library per architecture/libc target before linking sing-box.

## Unreleased — Smart probe/profile stability

- Share Smart probe admission across credential variants that describe the
  same provider endpoint; credentials remain excluded from the identity while
  endpoint address, port, TLS and transport stay part of the profile key.
- Preserve a bounded probe worker default for embedded/test constructors so a
  zero-value concurrency setting cannot silently disable all health checks.
- Add regression coverage for endpoint identity separation and credential
  rotation.

---

## 1.14.0-rc.1-official-smart-ebpf-v3.13-stream-recovery — 2026-08-26

- Wake the existing shared 204 recovery probe when an established Smart TCP
  stream reports a timeout, reset, broken pipe, or network-unreachable error.
- Do not directly penalize a node from a single stream error; ordinary EOF,
  local close, and cancellation remain neutral.
- Coalesce repeated errors from the same stream and add focused race-tested
  regression coverage.

## 1.14.0-rc.1-official-smart-ebpf-v3.12-recovery — 2026-08-26

- Wake one coalesced background recovery probe immediately after a real TCP
  dial failure, UDP setup failure, or response-expected UDP flow timeout.
- Keep same-request candidate failover on the data plane; recovery no longer
  depends on opening a dashboard or manually running a latency test.
- Add focused and race-tested regression coverage for failure wake-up and
  burst coalescing.

## 1.14.0-rc.1-official-smart-ebpf-v3.9-ingress-route — 2026-08-24

- Added `route.rules[].inbound_interface` so transparent PBR gateways route by
  the actual eBPF ingress interface instead of the unchanged client source IP.
- This permits a direct `eth0/pa-us/pa-jp/pa-sg/pa-other` to
  `HK/US/JP/SG/OT` mapping without SNAT or duplicated client subnets.

## 1.14.0-rc.1-official-smart-ebpf-v3.1 — 2026-08-21

### Official baseline

- Rebased the complete first-party Smart/eBPF/provider stack onto SagerNet
  official `testing` commit `712046a26` (`1.14.0-rc.1` snapshot).
- Adapted custom network listeners to the official asynchronous
  `InterfaceUpdated(context.Context)` lifecycle.

### Reproducibility and teardown

- Added the previously builder-only eBPF v3 control plane, TC program, runtime,
  static-rule sink, tests, and design document to Git; a clean clone is now
  sufficient to build v3.
- Continue route, backend and listener cleanup even when a TC detach reports an
  error; retained attachments remain retryable on a later close.
- Serialize live kernel generation synchronization with v3 flow/DNS/reload and
  close operations.
- Make `RouteMatchUnknown` a real bit so unknown rule classes fail closed rather
  than disappearing during bitwise accumulation.
- Preserve the outbound manager map/list invariant on failed removal.

### Build and validation

- GitHub release workflow builds four eBPF binaries: amd64/arm64 × glibc/musl.
- Linux `with_ebpf` tests, race, vet, and five repeated kernel data-path/load/
  policy-route collision gates pass before release.

---

## 1.14.0-beta.17-official-smart-ebpf-v3-profilefix.6 — 2026-08-21

### Smart cold-start availability

- Commit completed probe observations even when a bounded probe cycle reaches its deadline.
- Trigger one coalesced probe immediately after a provider publishes candidates; idle groups no longer wait for the periodic interval to build profiles.
- Publish the first successful basic probe while the rest of the group continues in the background, removing the cold-start request stall.
- Keep a candidate eligible after one or two basic-probe failures; isolate it only after three consecutive failures. Real traffic failures still feed the shared profile immediately.
- Publish probe-only profiles to the Clash API even when a region has no business traffic.
- Fix the confirmed-dead lookup to use the complete shared probe key before interrupting existing connections.

### Lifecycle and observability

- Make provider-owned outbound removal idempotent and remove the remaining invalid-index panic path.
- Close providers before the outbound manager so provider children can unregister safely.
- Treat normal fail-open proxy handoff as informational rather than an eBPF warning.

### Validation

- `go test`, `go test -race`, and `go vet` pass for the affected Smart/eBPF/outbound packages.
- VM115 cold-start gate: Google 204, Google Search, YouTube, and Cloudflare 204 succeeded from the macOS PBR path.

---

## eBPF data-plane v3 polish — 2026-08-21

Design: `docs/ports/EBPF-DATAPLANE-V3-DESIGN.md`. QA: Codex outputs `EBPF-V3-117-CANARY-QA-*.md`.

### Architecture (control plane = one sink)

- **Unified publisher**: `Lifecycle` + `DataplaneSink` dual-write memory model and kernel maps (no silent dual-brain).
- **DNS/prefill → v3**: `promoteLearnedBypass` also `PublishDNSHint` + `MergeStaticDirect` (active bank, no gen bump).
- **Static snapshot**: full `PublishStaticDirect` deletes removed LPM keys on inactive bank before commit.
- **Flow keys**: reverse published with `direction=0` + swapped 5-tuple (matches TC lookup).
- **Fragments**: never first-packet DIRECT; NEED_USERSPACE / parse-fail path.
- **PA default**: `capture_local` defaults **false** when `shared_network.enabled` (explicit true still allowed).
- **Interface reload**: one generation commit via static republish (no triple-bump).

### Canary

- 117: kernel `sb_v3_ingress` load OK after verifier fixes; soak with `capture_local=false`.
- 117 validated the isolated canary before staged VM115 deployment.

---

## 1.14.0-beta.17-official-smart-ebpf-perf — 2026-08-18

### 性能 / PBR 网关

- eBPF / shared-network **连接级日志** Info → Debug，避免网关刷盘
- **bypass miss 抽样**：对照静态 LPM；`kernel_miss` 告警；DIRECT 漏表 **gap_heal** `/32` promote
- `dns_prefill` 成功 promote 改 Debug；运行时指标保留
- Smart 探测去掉强制 `runtime.GC()`；冷启动探测默认 cap **45s**
- 脚本：`scripts/bypass-miss-sample.sh`

### 自洽 / HA（同周期）

- ConnectionManager 接通 **VerdictLearner + ConnectionSplicer**（此前注册未调用）
- **VerdictLearnerHub / ConnectionSplicerHub** 多 inbound fan-out
- Mixed shared-network learn 门控与 inbound 一致；`invoked` / `non_direct` 可观测
- Smart/selector/urltest/loadbalance/adaptive **NoteRealOutbound**；history **FinalizeChain** 记叶子
- Smart Close 有界等待，避免 `sing-box did not close!`
- Provider 重复 tag **内容稳定** `#`+hex 后缀
- Clash `GET /history` 根路径 → status

### 策略说明

- **不**合并 reF1nd 整树；纯官方 beta.17 + 自有端口
- AdaptivePool 继续 **PreMatchDisabled**（lease/观测语义）
- PBR 下 dial learn `writes≈0` 为预期（直连在 TC）

---

## 1.14.0-beta.17-official-smart-ebpf — 2026-08-17

### 基底

- 官方 `v1.14.0-beta.17` 干净树
- 注册：ProviderManager、ProviderOptionsRegistry、smart/eBPF/loadbalance/pass/history

### 功能端口

- Smart + AdaptivePool + eBPF DirectOffload（route + prefill + learn）
- DNSAnswerObserverHub / DirectOffloadHub
- MatchInputs 作用域 + RuleSet MatchClass
- connection_history + Clash `/history/*`
- loadbalance / pass

### 修复

- netlink Route.Src `*IPNet`
- provider 429 / NetworkList / anytls TFO 清理
- pre_match 测试恢复

---

## 更早线（摘要）

| 标签/线 | 备注 |
|---------|------|
| beta.14 / beta.15 smart-direct | 早期 DIRECT offload / mem 实验 |
| reF1nd overlay 尝试 | **已放弃**；改官方纯基底 |

---

## 升级提示（运维）

1. 二进制 tags 需含 `with_ebpf` + `with_connection_history`（完整网关）  
2. 生产建议：`log.level=info`（连接明细已在 Debug）  
3. Smart：`probe_interval` 30m+、`dns_prefill.ttl` 10m、history retention 可 72h  
4. 自检：`grep 'bypass miss sample' …`；`sh scripts/bypass-miss-sample.sh`  
## v3.42-score portability fix

- Pin Zig Smart release/test builds to the portable CPU baseline so binaries
  built on feature-rich hosts do not execute unsupported AVX instructions on
  older x86_64 virtual machines. Explicit `-Dcpu=native` remains available
  for controlled deployments.
