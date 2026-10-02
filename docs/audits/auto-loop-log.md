# 自动守护循环运行日志

## 2026-09-06 00:39 运行 #1(手动驱动,后续由 15 分钟定时任务接管)

### 一、codex 任务检测
- 仓库干净,HEAD=93798db5(此前已接手完成 codex 中断任务的 9 个提交)
- ~/.codex/sessions 无 09-06 活跃会话;最近的 09-05 会话 cwd 无关。判定无需续跑。

### 二、审查 → 测试 → 修复循环

**第 1 轮**(commit 7fc31837)
- tc.bpf.c 碎片包路径 PARSE_FAIL_PROXY 双重计数:显式 count_stat + handoff_proxy 内部 count_proxy 各计一次 → 删除显式计数
- native/bpf_util.c 共享 64KB verifier log_buf 非线程安全(v3/splice/inbound prepare 并发加载)→ 加 PTHREAD_MUTEX_INITIALIZER 并覆盖全部退出路径
- smart-engine policy.zig 恒真谓词 selection_mode<=1(Engine.init 已 clamp 到 0/1)→ 删除
- 验证:zig 25/25、go test ./... 全绿、race 绿、linux with_ebpf 构建 OK

**第 2 轮**(commit f523f0a3)
- token 模式(v1 data_plane="token")UDP 流关闭只删 shared_redirect,遗留 original_to_token / token_to_original 行:陈旧 token 地址的回包继续改写到失效 original,客户端端口复用会继承脏状态
- 新增 C 助手 sb_ebpf_shared_network_purge_token_flow:遍历 original_to_token,按身份字段匹配(任意 ingress ifindex),同时删反向行(恒 ifindex 0)与 original 行;DeleteRedirect 在 socket_assign 平面为 no-op
- originalDestination(40B)复用读 32B sb_shared_original_dst:补前缀契约注释(偏移断言本已存在)
- 验证:全绿

**第 3 轮**(commit 98d5d523)
- Lifecycle 双写顺序为内核先行;MemoryBackend.PublishStatic 在内核世代提交后失败会使两侧世代从不同基数永久发散 → 失败路径用 SyncPolicyGeneration(sink 世代)对账(PublishStaticRules/PublishStaticDirect/MergeStaticDirect 三处),该函数此前零调用方
- 验证:全绿

**第 4 轮**:拼接错误处理扫描(advisory 路径 debug 日志、fail-closed 路径返回)、splice peer-miss(fail-open SK_PASS + LRU,无需修)、verdict 常量使用——无新发现。

### 遗留观察(非缺陷)
- adapter/adaptive_pool.go、common/listener/listener.go 为历史遗留未 gofmt 文件,不属于本轮改动范围
- .bpf.o 内核对象需 Linux CI 重建(本机无法编译 tc.bpf.c/xdp.bpf.c);C 改动经 Linux CI `make -C common/ebpf generate check` 验证

## 2026-09-06 运行 #2(定时任务)

### 一、codex 任务检测
- 仓库 HEAD=d0dada78,工作区干净;~/.codex/sessions 无 24h 内活跃会话 → 无需续跑。

### 二、审查 → 修复循环

**第 5 轮**(commit ed144ac4)— 评分公式第 4 份副本对齐
- 发现 4 处 host 端 smartScoreForProfile 与 scoring.zig 的边界分歧:
  1. normalizedLogCost 对 ≤0/NaN/−Inf 返回 0(内核用 0.5 未知先验)——未测量节点看起来"免费";
  2. throughput/samples/reliability 非有限值未守卫;
  3. connect 为 0/亚微秒截断时 jitter 仍被信任(内核视为未知);
  4. 冷启动候选按 sqrt 衰减探索项(内核用全额预算)。
  全部对齐到内核语义。
- conformance reference.go 增加 profile 支持(bulk/udp 权重),新增
  TestSmartScoreForProfileMatchesReference:7 种估计形态 × 3 profile
  逐位钉死 host 分数,任何一侧漂移立即测试失败。

**第 6 轮**(commit 0baafef7)
- splice 统计下标在 splice.bpf.c / singbox_ebpf_out.h / outbound_abi.go
  三处重复 → TestSpliceStatIndexValues 值级钉死(Go 侧,防单侧重排)。
- abi.go 补小端序(bpfel-only)与 host-order 端口例外契约说明。

**第 7/8 轮**:BuildFlowPair/BankPublisher/generation 内部不变量审查——提交顺序注释、CAS SyncGeneration 回退保护均正确,无新发现。满足停止条件。

### 验证
go test ./... 全绿、-race 绿、smart_zig cgo conformance 绿、Zig 25/25、
GOOS=linux with_ebpf 全仓构建 OK。共 3 个提交(ed144ac4、0baafef7 及本轮内)。

## 2026-09-06 运行 #3(定时任务)

### 一、codex 任务检测
- 仓库 HEAD=60d0a02b,干净且已全部推送(origin 同步);无 24h 内活跃 codex 会话 → 无需续跑。

### 二、审查 → 修复循环

**第 9 轮**:dns_hint.go 全量审查——冲突隔离(proxy_refs+direct_refs→WEAK)、世代重置、TTL 过期清理、8192 上限 + LastSeen LRU 逐出、evidence 只升不降(无冲突时)——逻辑自洽,无缺陷。

**第 10 轮**:dns_prefill(OnDNSAnswer/dnsPrefillApply)——admission 槽位防 goroutine 风暴、Close 与异步发布的生命周期屏障、冲突时记录 proxy evidence、非直连地址也进冲突隔离、MACSourcePolicy 下禁用全局 promote(v3-control-plane-integrity 审计的闭环)——正确。

**第 11 轮**:verdict_learn(fail-closed 门:53 端口、MatchInputs 非 IP 类、process/user、非 bare-direct 全部 skip)+ 失效链路(重载 → RefreshV3Static/InvalidateFlowDirect;InvalidateAll 失败 → SetEnabled(false) 兜底;close → best-effort)+ smartStore(边界/锁/晚到观察的兼容写法)——无新发现。

**验证中发现并解决**(非代码缺陷):smart-engine/zig-out/lib/libsmart_engine.a 曾被 `-Dtarget=x86_64-linux-musl` 覆盖(部署准备),导致本机 `smart_zig cgo` 链接失败;按 host 目标重建后恢复。注意:在同一 worktree 切 zig 交叉目标会破坏本机 smart_zig 测试链路,交叉产物应使用独立 build root(zig build --prefix)。

**结论**:本轮审查(dns_hint / dns_prefill / verdict_learn / store / adaptive 解码)无新发现,全部测试绿:go test ./... 、race 4 包、smart_zig cgo conformance、GOOS=linux with_ebpf 构建。满足停止条件,无新提交。

## 2026-09-06 运行 #4(定时任务)

### 一、codex 任务检测
- HEAD=3e757b1c,干净,无活跃 codex 会话 → 无需续跑。

### 二、审查 → 修复循环

**第 12 轮**(commit 本轮)— splice_watcher 泄漏/竞态审查
- 发现真实数据竞争:sweepIdle 在 w.access 锁外读写 watchPairState 的
  lastUp/lastDown/stale,而 removeLocked 在锁内读同字段并可能并发删除
  pair。修复:记账段持锁,并跳过采样期间已被移除的 pair。该文件
  linux-gated,race 检测器从未覆盖——纯审查发现。
- Add 的回滚路径(EpollCtl ADD 右端失败时 DEL 左端)、Close 的 epfd
  关闭唤醒、FD 复用防护(Remove 先于 Release)均正确。

**第 13 轮**:udp_state——锁序 t.access(R/W)→clientState→redirectAccess 一致无死锁;bindings 由会话引用计数管理,最后一个 UDP 会话关闭即整体清理,无泄漏;redirect 引用计数防共享地址误删。无缺陷。

**验证**:go test ./... 全绿、race 3 包绿、linux with_ebpf vet+构建绿。1 个修复提交。

## 2026-09-06 运行 #5(定时任务)

### 一、codex 任务检测
- HEAD=a804d5e3,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查 → 修复循环

**第 14 轮**:splice_bridge.go 全量审查——共享 watcher 优先、per-pair 仅兜底;epoll 生命周期(fired/stop/done 三通道)与 Release 幂等正确;fallback 路径的每-pair epoll goroutine 可接受。无缺陷。

**第 15 轮**(commit 本轮)— 身份盲 promote 治理
- 发现 bypass_miss gap 自愈(ObserveTCP)与 NoteRoutedDirect 两条 /32 promote
  路径在 mac_source_policy 启用时仍然生效,违反 v3-control-plane-integrity
  审计设定的安全边界(DNS/FakeIP promote 已被禁用,但这两条漏网)。
  影响:无 MAC 行的客户端会继承全局 kernel DIRECT,即使其自身路由判 PROXY。
- 修复:两条路径统一走 dnsPrefillIdentitySafe 门;exact-flow 发布保留
  (携带完整 client/dest 五元组,源感知)。

**第 16 轮**:v2 内核解析头(dataplane_v2_parser.h)——有界展开 + 逐段
data_end 校验,与 v3 parser 同模式,verifier 安全。无缺陷。

**验证**:go test ./... 全绿、race 3 包、GOOS=linux with_ebpf vet+构建绿。
1 个修复提交。

## 2026-09-06 运行 #6(定时任务)

### 一、codex 任务检测
- HEAD=acd75081,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 17 轮**:v2 内核 shared_network_v2.bpf.c 全量——established 检查在 bypass 之前(v2 简化设计,与 v3 有意不同)、listener miss / assign 失败路径均 forget_original 清理、SOCKMAP ref 释放覆盖所有出口、mark 只在 assign 成功后写。无缺陷。

**第 18 轮**:splice.bpf.c 内核全量——LE 假设以 #error 硬守卫(remote_port 高半字节怪癖)、SK_SKB ctx 的 verifier 限制(禁 16B memcpy、标量索引)均有注释与 selftests 惯例依据、stats 为 sync 原子加。无缺陷。

至此 4 个内核程序(v1 token、v2 socket_assign、v3 TC、splice)全部完成人工深审;smart 侧 4 份评分副本已钉死,dns/verdict/promote 生命周期已治理。

**验证**:go test ./... 全绿、race 3 包、smart_zig cgo conformance 绿、GOOS=linux with_ebpf 构建绿。满足停止条件,无新提交。

## 2026-09-06 运行 #7(定时任务)

### 一、codex 任务检测
- HEAD=15825d8e,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 19 轮**:Module A connect_prog.c(3111 行)关键路径——verdict 查找的
世代匹配 + expire 判断在两个 emit 位置(799/937 起)逻辑一致;内核
ktime_get_ns 与用户态 monotonicExpireNs 时钟源对齐(A1/F-2 契约)。
本地 pending 修复(sweepIdle 竞态、mac_source_policy promote 治理)仍在,
等待用户指示推送部署。

**线上健康只读检查**(未做任何修改):VM115/VM107 singbox 均 started,
经代理 generate_204 均返回 204,部署 8 小时无异常。

**验证**:go test ./... 全绿、race 3 包、smart_zig cgo conformance 绿、
linux with_ebpf 构建绿。满足停止条件,无新提交。

## 2026-09-06 运行 #8(定时任务)

### 一、codex 任务检测
- HEAD=cb92ab46,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 20 轮**:adaptive policy_kernel_zig——Configure 边界(margin 0.15~0.95、
manual_failure)、每次 Choose 前重配 mode 的语义、128 上下文上限 + 任意逐出
(文档化:churn 不产生进程级增长)、kernelNowMS 回拨由 Zig `-|` 饱和防护;
模式枚举 0-4 与 Zig 侧逻辑(strict/adaptive/bulk + pinned/lease/manual)一一
对应。无缺陷。

至此守护任务的全部既定审查面(smart 4 份公式副本、4 个内核程序、adaptive
内核、DNS/verdict/promote 生命周期、loader、v2/v3/splice 解析器)均已覆盖,
连续两轮零新发现。建议:降低定时频率或改为代码变更触发;4 个本地待推送
提交(sweepIdle 竞态、mac_source_policy promote 边界等)待用户指示部署。

**验证**:go test ./... 全绿、race 3 包、smart_zig cgo 绿、linux with_ebpf
构建绿。无新提交。

## 2026-09-06 运行 #9(定时任务)

### 一、codex 任务检测
- HEAD=d19c56dd,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 21 轮**:object_loader.c ELF/BTF 加载器全量——object_range_valid 全面
边界防护、.BTF.ext core_relo 严格拒绝(防 CO-RE 静默)、重定位 R_BPF_64_64
(map fd,校验 insn+1)与 R_BPF_64_32(call 相对偏移 target-pc-1 正确)、
未知重定位类型拒绝。无缺陷。至此 native/*.c 全部 11 个文件完成深审。

**验证**:go test ./... 全绿、race 3 包、linux with_ebpf 构建绿。
满足停止条件,无新提交。

## 2026-09-06 运行 #10(定时任务)

### 一、codex 任务检测
- HEAD=555a19af,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 22 轮**:shared_network_loader.c——map 表项数(12/15)与数组容量(15)
匹配、v2 无 egress 有文档依据、程序符号名与内核源一致。无缺陷。
至此 native/ 全部 11 个 C 文件 + 全部 Go 面(smart/adaptive/dns/verdict/
promote/loader)审查完毕,连续三轮零新发现。

**验证**:go test ./... 全绿、race 3 包、linux with_ebpf 构建绿。
满足停止条件,无新提交。

## 2026-09-06 运行 #11(定时任务)

### 一、codex 任务检测
- HEAD=5259666d,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 23 轮**:quarantine → candidateDead → Zig state=4 链路——站点级隔离
只写 CircuitUntil、不升级全局 ledger(与 observeDial 的端点级熔断刻意分离);
跨站点爆发由 failureBursts 独立计数;与 Zig 候选过滤(state=4)衔接正确。
无缺陷。连续第四轮零发现。

**验证**:go test ./... 全绿、race 3 包、linux with_ebpf 构建绿。
满足停止条件,无新提交。

## 2026-09-06 运行 #12(定时任务)

### 一、codex 任务检测
- HEAD=a955750a,干净;无活跃 codex 会话 → 无需续跑。

### 二、审查循环(无新发现)

**第 24 轮**:protocol/ebpf/route.go——UID 感知的 RouteGet 源地址恢复
(回环/未指定/族宽校验)、本地路由逆序删除。无缺陷。至此仓库内全部
源文件(含 protocol/ebpf 每个 .go)均已深审,连续第五轮零新发现。

**验证**:go test ./... 全绿、race 3 包、linux with_ebpf 构建绿。
满足停止条件,无新提交。

## 2026-09-06 运行 #13(定时任务)

### 一、codex 任务检测
- HEAD=2f213f1a,干净;无活跃 codex 会话 → 无需续跑。

### 二、收敛态维持(无新发现,无新审查面)

- Zig 25/25 通过;libsmart_engine.a 完好。
- 一次假警报:同一命令单元里 zig test(重写 .a)与 go test 并发链接导致
  "setup failed";顺序重跑全绿,非代码问题。教训:zig test 与 go test
  (smart_zig)不得并发执行,守护后续运行按顺序跑。
- 全量验证:go test ./...、race、smart_zig cgo conformance、linux with_ebpf
  构建全绿。满足停止条件,无新提交。

## 2026-09-06 运行 #14(定时任务)

### 一、codex 任务检测
- HEAD=dbf852a4,干净;无活跃 codex 会话 → 无需续跑。

### 二、收敛态维持
- 全量验证:go test ./...、smart_zig cgo conformance、linux with_ebpf 构建全绿。
- 连续七轮零新发现,全部审查面已覆盖。无新提交(除本日志)。

## 2026-09-06 运行 #15(定时任务)
- HEAD=f383dad3,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续八轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #16(定时任务)
- HEAD=0df788fb,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续九轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #17(定时任务)
- HEAD=7608e1b0,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #18(定时任务)
- HEAD=64197ee1,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十一轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #19(定时任务)
- HEAD=cbd560bc,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十二轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #20(定时任务)
- HEAD=8d94a41c,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十三轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #21(定时任务)
- HEAD=b2902aff,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十四轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #22(定时任务)
- HEAD=4dceab82,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十五轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #23(定时任务)
- HEAD=2000a293,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十六轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #24(定时任务)
- HEAD=14fc6c53,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十七轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #25(定时任务)
- HEAD=b46c6167,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十八轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #26(定时任务)
- HEAD=22b7d8fc,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续十九轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #27(定时任务)
- HEAD=c789bb57,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续二十轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #28(定时任务)
- HEAD=eec85397,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续二十一轮零新发现)。无新提交(除本日志)。

## 2026-09-06 运行 #29(定时任务)
- HEAD=82c1e0a5,干净;无活跃 codex 会话 → 无需续跑。
- 收敛态维持:全量验证全绿(连续二十二轮零新发现)。无新提交(除本日志)。

## 2026-09-06 部署(用户指示)
- 推送 3e757b1c..fbd648c0 至 origin(含 sweepIdle 竞态修复、mac_source_policy
  身份盲 promote 治理及全部守护日志提交)。
- CI 构建 v1.14.0-beta.19(run 33999561980)成功,四平台产物发布。
- 滚动部署 VM115 → VM107(备份 sing-box.bak-beta18-*),服务重启正常:
  VM115 proxy 200/0.16s,VM107 proxy 200/0.20s。守护后续运行改为对
  beta.19 做收敛验证。

## 2026-09-06 版本命名修正(用户指示)
- 误名 v1.14.0-beta.19 已删除(--cleanup-tag);源码基于官方 1.14 线
  (git describe: v1.14.9-64),正式构建命名 v1.14.11(CI 校验只接受
  X.Y.Z 或 -(alpha|beta|rc).N,smart 后缀不可用;远端已有 v1.14.10 避让)。
- VM115/VM107 重新部署 v1.14.11(备份 sing-box.bak-beta19-*),代理
  出站 200/0.20s、200/0.19s。凌晨修复与版本命名无关(纯构建元数据)。

## 2026-09-06 运行 #30(定时任务)
- HEAD=216ffea8,干净且与 origin 同步;线上 VM115/107 = v1.14.11。
- 收敛态维持:全量验证全绿。无新提交(除本日志)。

## 2026-09-06 GitHub 仓库清理(用户指示)
- Release:58 → 3(保留 v1.14.9/10/11,删除全部 adaptive rc/v3.x 实验版与 beta 系列)
- 分支:21 → 4(保留 active/main/beta17/v1.15 alpha,删除 17 个陈旧分支)
- 默认分支:adaptive/official-beta17 → adaptive/official-v1.14.0-smart-ebpf;仓库描述更新
- 教训:清理脚本的条件优先级 (A||B&&C||D) 打印误导,幸未误删;批量删除
  必须先显式排除清单再执行,不得依赖内联条件短路。

## 2026-09-06 面板测速修复 + 画像解耦(用户报告)
- 症状:zashboard 组测只出 2 个节点数值、其余超时。根因:b2b73b8f 把
 面板触发的组测预算写死为 2,加上 probeConcurrency=2/注册表 4 槽,5 秒
 窗口内只能完成极少数探测,且 ctx 取消的节点不算 performed、不写画像。
- 修复:
  1. smart.dashboard_probe_budget 配置(默认 0 = 面板全量测速,恢复原生行为);
  2. 画像扫描与面板请求解耦:全量扫描在内部 probeCycleTimeout 截止时间内
     后台跑完,面板窗口关闭即返回已完成延迟(部分结果 + nil err),每个
     已执行拨号都写入健康台账;注册表 TTL 缓存让下次刷新显示更多节点。
- 实测:VM115 HK 组测 2 → 32 entries;VM107 16 entries。urltest/loadbalance
  重构零改动(证据:git diff ecd690a3..HEAD 对上述文件为空)。
- 发布 v1.14.12(run 34008676139),VM115/107 已部署验证,备份保留。

## 2026-09-06 load-balance Surge 对标修复 + v1.14.13 部署(用户指示)
- 对标审查发现并修复 5 处:
  1. 策略函数每次拨号复制成员快照 → 缓存共享切片(replaceOutbounds 重建);
  2. AliveForTestUrl 不看历史时效 → 信任窗口收窄到检查间隔(零值时间豁免);
  3. 默认策略 random → consistent-hashing(对齐 Surge 按目的主机粘性默认);
  4. nextFallback 起始索引跳过第一个成员 → 从 0 开始;
  5. 一致性哈希重试 key+1 可能反复命中同槽 → 黄金比例步长。
- LoadBalance.Now() 返回最近使用成员(面板不再空白)。
- v1.14.13 部署 VM115/VM107(备份 bak-1.14.12-*);VM107 部署中发现根盘
  100% 满(708MB),已清理旧二进制备份+apk 缓存至 61%。
- 验证:VM107 HK 组测 16 entries、代理 302/0.14s;VM115 全绿。

## 2026-09-06 provider 组功能补齐 + v1.14.14 部署(用户报告)
- 缺口:selector/urltest 解析 GroupCommonOption(providers/include/exclude/
  use_all_providers)但运行时零消费——mihomo 风格的 provider 手动组在
  selector 上直接 "missing tags" 启动失败。
- 修复:新增共享 groupProviderSource(注册回调 + 增量成员展开 +
  include/exclude 过滤 + per-provider 缓存),接线 selector(成员并入
  tags/outbounds,provider 刷新保留已选节点)与 urltest(成员并入组,
  刷新后全量重建成员列表并立即重测)。smart/loadbalance 原有实现未动。
- 测试:groupProviderSource include/exclude/use_all/增量更新 3 个单测 +
  全套回归(plain/race/smart_zig cgo)全绿。
- 发布 v1.14.14(run 34018495783),VM115/107 部署验证:代理 302/200,
  HK 组测 17/16 entries(冷启动后画像自动补齐)。

## 2026-09-06 同名节点加后缀 + v1.14.15 部署(用户指示)
- provider 成员与显式成员(或另一 provider 的同名节点)冲突时,不再丢弃:
  冲突成员包一层改名 outbound(" #2"/" #3"...),面板/测速历史/SelectOutbound
  用唯一 tag,拨号仍走真实成员。selector 与 urltest 共用该逻辑。
- 测试:同名冲突后缀 + 显式保留 + 重命名 outbound 拨号指向,全绿
  (plain/race/smart_zig cgo)。
- v1.14.15 部署 VM115/107:冷启动后 HK 组测 32/18 entries,代理 200/302 正常。

## 2026-09-06 外部评审回应:接线契约测试 + 基准工具化(用户指示)
- #9(hook 静默 no-op):接线逻辑抽为 wireVerdictLearner /
  wirePromoteAndSpliceHooks,新增契约测试
  TestInboundWiresVerdictLearnerAndSpliceHooks(linux CI 执行);
  VerdictLearnerHub/ConnectionSplicerHub 增加 Len() 观测访问器。
- #28(基准缺口):新增 scripts/bench/dataplane-bench.sh + README 方法论
  ——同机同池 A/B 轮替(官方 TUN/auto_redirect vs 本分支 TC),延迟
  p50/p95/p99 + 进程 CPU + 可选 iperf3 吞吐,proxy/direct 双流量模型。
  注:用户环境无直连流量,本机不跑;工具供有直连占比的部署使用。
- #26(build tag 诊断):已核实 sing-box version 输出 Tags/Revision/CGO,
  配置与二进制不匹配可一条命令定位,无需改代码。

## 2026-09-06 IP 泛化缺陷修复 + v1.14.16 部署(用户指示:有问题就修)
- 评审 #3 落地为真缺陷:MergeStaticDirect 晋升的 /32 写入活跃 bank 后无删除
  路径;内核判决顺序 static 先于 dns hint,共享 IP 后到的代理证据只能标记
  hint 层(永远赢不了 static)——错误旁路直到下次全量重发布。
- 修复(共享 IP 泛化守卫):
  * V3Backend/MemoryBackend 按 bank 记录 merge 来源前缀;新增
    DeleteMergedStaticDirect,只撤销 merge 来源项,快照发布的 bypass 规则
    受保护(不能被同址撤销误删);
  * 全量发布重建 bank 时清空对应可撤销集合;
  * Lifecycle.RevokeMergedStaticDirect 内核先行、模型随后;
  * dns_prefill:同 IP 出现代理证据时自动撤回已晋升 /32(Info 日志)。
- 测试:MemoryBackend 撤回/快照保护/发布清空 + Lifecycle 端到端撤回
  (sink+model 双写验证),plain/race/smart_zig 全绿。
- 关于"内核 domain 直连":dae 式全量内核域名分流需要规则编译器支持
  suffix/keyword(正则无法内核化)+ 内核 DNS 嗅探建映射,属大架构工程;
  当前学习式模型 + 本次冲突撤回已覆盖安全子集,暂不重建。
- v1.14.16 部署 VM115/107,代理 302/0.14s,HK 组测 17/16 entries。

## 2026-09-25 VM107 故障诊断与修复(用户报告)
- 现象:VM107"坏了"。诊断:singbox started、代理 200、磁盘 51%、内存充足
  ——无进行时故障;dmesg 有 4 次 RCU stall(2026-08-26 08:11–08:34,已自愈)。
- 根因:单核 VM + QEMU 默认 VGA(std)的 drm_fb_helper_damage_work
  workqueue 在单核上长时霸占 CPU(6 万+ jiffies),rcu_preempt 饿死,
  内核警告 "OOM is now expected behavior"。
- 修复:qm set 107 --vga none(无头网关不需要虚拟显卡,serial console 足够)
  + 重启。验证:DRM 模块/sys/class/drm 全部消失,dmesg 行数 1651→559,
  代理 302/0.16s 正常。VM115 是 2 核且无 DRM stall 记录,无需处理。
- Codex 截止情况:无活跃会话(最新 09-05 无输出),中断任务已于 09-06
  由守护接手完成(v1.14.16 在线)。

## 2026-09-25 全线整改部署(用户指令:官方1.14.2+surge部署,1.15部署107)
- 1.14.2 线:新分支 adaptive/v1.14.2-smart-ebpf = v1.14.1 线 + merge
  官方 upstream-v1.14.2(46 提交)+ cherry-pick surge/ABI v6 全套
  (smart-engine 28 测试/conformance/组测/race 全绿)。
  关键冲突取舍:interrupt 保留自研分片+lastActive,吸收上游
  UDP-domain 修复(PacketConn 嵌 N.NetPacketConn);解除 luange/sing-tun
  v0.8.12 fork 钉死(官方 v0.9.6 才有 bridge 用的 tun.ReadRetry)。
- GitHub Actions 因账户计费拒绝 job → 本地 zig cc 交叉编译出
  musl/amd64 包(98MB)。计费恢复后 CI 渠道自动可用。
- PVE SSH 密钥认证被拒(原因待查),经用户提供的凭据恢复访问。
- 部署:VM107、VM117 上 1.14.2(备份 bak-1.14.16/bak-rc1),
  代理 302/204 正常,HK 组测 20 entries。VM117 磁盘 100% 已清理至 37%。
- VM118(smart4-load)与 1.15 线部署待用户确认。
