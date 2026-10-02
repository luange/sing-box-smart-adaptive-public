# eBPF/TC 对照学习与性能补足（2026-08-31）

## 对照结论

本次对照只吸收架构原则，不复制其他项目的实现。Linux BPF map 支持
`PERCPU_ARRAY`、`LRU_HASH` 等类型，适合把高频计数和有界状态分开；策略真值仍须
保持跨 CPU 一致，不能为了计数性能把策略 map 变成多份。

| 维度 | 成熟实现的共同原则 | 本项目当前实现/边界 |
| --- | --- | --- |
| 内核路径 | 固定分类，命中后尽量短路；未知或不安全时回落 | v3 只把已确认 DIRECT 交给快速路径，PROXY、解析失败、代价不明统一回落 TC/用户态 |
| 统计 | per-CPU 累加，读取时聚合，避免逐包全局锁 | `v3_stats` 为一个 per-CPU 32 项向量；一次 map lookup 聚合，用户态 scratch 缓冲复用 |
| 连接状态 | 固定上限、LRU/TTL、空闲不忙轮询 | DNS/exact-flow 用户态镜像各 8192 条，TTL 清理、最老项淘汰，generation 变更同步清理 |
| 多队列 | RX queue 与 CPU/XSK 槽位一一对应，能力不足不强启 | XDP 探测区分 driver/generic、zerocopy/copy、队列数和空槽；不满足条件回落 TC |
| 代理流量 | 不把代理协议伪装成直连加速；透明分流与代理转发分层 | 代理、未知、弱 DNS 证据不进入 XDP；TC 只做分类/回程，代理协议仍由 sing-box 处理 |
| 空闲行为 | 不以无条件 busy-poll 换取理论吞吐 | 无常驻忙轮询；统计和过期清理由现有周期任务驱动 |

## 这轮实际补足

`V3Backend.readStatsLocked` 以前每次都创建 `possible-CPU × 256B` 的临时切片。周期
`RuntimeStats` 会在高频观测下反复制造短命对象，放大 GC 和 RSS 波峰。本轮改为：

1. 初始化时分配一个按 possible CPU 数量计算的 scratch 向量；
2. 用独立 `statsAccess` 互斥保护 `RuntimeStats` 与 `V3Stats` 并发读取；
3. 单次 map lookup 写入 scratch，再在本地数组中聚合；
4. 仅 `V3Stats` 为兼容既有 API 复制 32 个最终计数，`RuntimeStats` 不再复制整块 per-CPU 数据。

这不改变选路、TTL、generation 或 fail-open 语义；若内核 map 读取失败仍返回错误/空快照，
不会把不完整计数当作有效策略依据。

## 性能验证方法

不能用不同机器或不同协议流量直接宣称“快了多少”。Linux CI/PVE 的比较必须固定：

- 同一内核、网卡队列、MTU、CPU 绑核和配置；
- 同一 TCP/UDP/DNS/QUIC 流量回放；
- 记录首包/首字节 p50/p95、吞吐、丢包、`socket_assign` 失败、map reject；
- 用 `bpftool prog profile` 记录 instructions/cycles/cache-misses；
- 用 RSS、HeapAlloc、goroutine、FD 和 map entries 观察稳态及 30 分钟峰值。

对照对象的公开资料只用于校验方向：Katran 的重点是 per-CPU/多队列和有界连接状态；
dae 的重点是 TC 内核分流和直连绕过用户态，而不是把代理转发搬进 XDP。当前实现因此保留
TC 作为生产兜底，XDP 仍只在能力探测通过且明确 DIRECT 时启用。

## 未宣称的结果

本记录没有伪造吞吐或延迟数字。要形成数值基线，必须在 Linux 上进行同机 A/B 测试；在
没有固定流量和硬件条件前，任何“比 dae 快/慢”的数字都不具备可比性。

