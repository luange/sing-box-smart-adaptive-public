# eBPF v3 性能整改记录（2026-08-31）

## 结论

当前生产候选仍以 TC v3 为主。性能瓶颈首先在逐包统计和共享 map 写入，而不是
继续强行启用 AF_XDP。代理、未知、解析失败和不满足资格的流量继续回落 TC；
只有已确认 DIRECT 的流量才允许进入可选 XDP 路径。

## 本轮已实施

1. `v3_stats` 改为 `PERCPU_ARRAY[1]`，每 CPU 保存一个 32 项计数向量。内核计数
   不再对共享 cache line 做原子 RMW。
2. DIRECT 和 PROXY 动作各自合并为一次统计 map lookup；PROXY 的 reason、packet、
   byte 三项在同一向量内更新。
3. 用户态一次读取全部 CPU 的向量并聚合，避免每个 counter 单独发起 map syscall。
4. socket assignment 被关闭时不再执行 `skc_lookup_tcp`，控制面的 feature mask
   对数据面保持一致。
5. v3 ABI 升为 2，旧的 stats map 布局拒绝热接管，避免静默读错指标。
6. DNS hint 在 TTL 到期后开启新的证据 epoch，并把用户态镜像限制在 8192 条；
   旧的 proxy/direct 冲突不会永久污染复用的 CDN 地址，长期运行也不会无界增长。
7. exact-flow 用户态镜像按 8192 条双向 entry 限制，周期清理过期项，并在策略
   generation 提交/失效时同步删除旧 flow 与 DNS 镜像；内核仍使用自身 LRU 和
   generation 检查。
8. v3 统计读取复用按 possible-CPU 数量分配的 scratch 缓冲，并用独立锁保护
   并发读取；周期 `RuntimeStats` 不再为整块 per-CPU 向量反复创建短命切片。

这些改动只回收已过期或已失效的用户态镜像，并改变 telemetry 的存储方式和无效
路径开销，不改变静态策略、Smart、DNS 冲突隔离、socket assign、失败回落或策略
generation 语义。

## 对照成熟项目后的保留边界

- Linux AF_XDP 的四个 SPSC ring、`need_wakeup` 和共享 UMEM 规则继续遵循内核
  语义；没有通过增加无界用户态队列换取吞吐。
- libxdp dispatcher 的多程序原子共存尚未接入，因此 attach 仍拒绝覆盖已有 XDP
  程序，避免破坏宿主网络。
- Katran 的 Per-CPU map 和多队列思路用于统计/扩展方向；策略真值仍使用共享
  双 bank，以保持跨 CPU 一致性。
- 不把策略 map 改成 Per-CPU、不周期性无条件 `FreeOSMemory`，也不默认丢弃
  QUIC/UDP/443；这些会改变路由或协议语义。

## Linux 验证门

必须在 Linux CI/PVE 完成，禁止用 macOS 产物替代：

```sh
make -C common/ebpf generate
make -C common/ebpf check
go test ./common/ebpf/v3 ./protocol/ebpf/v3
go test -race ./protocol/group/...
bpftool prog profile id <tc-prog-id> duration 30 cycles instructions cache-misses
perf stat -e cycles,instructions,cache-misses ./sing-box check -c <isolated-config>
```

对比整改前后：每包 cycles、instructions、cache-misses、首包 p95、吞吐、丢包、
`socket_assign` 失败、map capacity reject 和内存。只有在行为门全部通过且性能
基线不回退时，才进入测试实例部署；本记录不授权生产 VM 变更。

## 本轮 Linux 证据与部署记录

- 提交：`173f6e642bd0429d707d75410acb404c7d36f3df`。
- 全局审查：GitHub Actions `33343881157`，eBPF provenance、聚焦测试、竞态、
  `go vet` 和 Zig conformance 全部通过。
- 构建矩阵：GitHub Actions `33343890576`，amd64/arm64 × glibc/musl 全部通过；
  产物 SHA-256 位于 `/Volumes/WeChat/CodexBuild/artifacts/173f6e64-stats-scratch-1/`。
- 已按原子替换部署到 107（amd64-musl）和 115（amd64-glibc），版本均为
  `1.14.0-rc.5-official-smart-ebpf-v3.47-stats-scratch`。
- 部署后只读验收：两台服务均 `started`；9090=200，9091/9092 为预期 3xx；
  115 的 pa-hk/pa-us/pa-jp/pa-sg/pa-other 均保持 TC v3 ingress，未启用 XDP。
  采样 RSS 约 86.9 MiB（107）/87.8 MiB（115），线程 7/8；重启后错误关键词为空。
- 回滚副本：`/Volumes/WeChat/CodexBuild/rollback/2026-08-31-173f6e64/`，并在两台
  VM 的 `/root/singbox/sing-box.before-173f6e64` 保留同一份校验过的旧核心。

### 画像工具边界

115 的内核已确认程序为 JIT `sb_v3_ingress`（13,801B），但自有 ELF loader 不把
调试 BTF 绑定到已加载程序，因此该主机上的 `bpftool prog profile` 会返回
`prog ... doesn't have valid btf`。这不是数据面加载失败，也不应为了画像强行引入
libbpf 运行时依赖；当前采用 `perf stat -p <sing-box-pid>`、TC/map 计数和 RSS/Heap
时间序列作为兼容的观测路径。107 未安装 `bpftool`，本轮不改系统补装工具。
