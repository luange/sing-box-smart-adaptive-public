# RC4 全局审查记录（2026-09-05）

本轮基线为官方 sing-box `v1.14.0-rc.4`，审查范围覆盖 Smart/Smart
Zig、eBPF v3 控制面、DNS 预填、学习型直连、连接生命周期以及 XDP/TC
边界。没有修改 107/115，也没有在 macOS 编译 eBPF 或 XDP 对象。

## 已确认并整改

1. Smart 的 TCP/UDP 观察器现在携带请求上下文。调用方取消或请求截止导致的
   `context.Canceled`、`context.DeadlineExceeded`、`os.ErrDeadlineExceeded`
   不再被记录为节点故障；独立的 socket 超时仍保留为有效质量证据。响应看门狗、
   建连后停顿计时器和关闭时的合成无响应路径均遵守同一边界。
2. eBPF 学习型直连的 Go 表与 TC/v3 镜像改为可重试事务。后端重建失败时恢复
   原表；TTL 回收只在后端提交成功后删除过期项；v3 合并在父级 bypass 更新成功
   后执行，避免半提交造成“状态显示已生效、内核实际未生效”。

## 验证结果

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go test -tags with_ebpf ./common/ebpf/v3 ./protocol/ebpf/v3 ./protocol/ebpf`
- `go test -race -tags with_ebpf ./common/ebpf/v3 ./protocol/ebpf/v3 ./protocol/group`

以上均通过。新增回归测试覆盖过期请求截止、UDP 看门狗、学习直连回滚和
v3 静态镜像一致性。

## Linux 门禁与边界

提交后由 `rc4-global-audit.yml`、`smart-engine.yml` 和 `xdp-engine.yml`
在 Linux 上完成 Zig/CO-RE/BTF/eBPF verifier 与交叉构建验证。TC 解析失败仍按
兼容性策略“无标记放行”，不擅自改为 DROP；AF_XDP 仍是实验性 DIRECT 快路径，
代理、未知、畸形、分片流量回落 TC，未挂载到生产 VM。

本轮 Linux 门禁已通过：全局审查 `33964265688`、Smart Zig
`33964157515`、XDP `33964171036`。期间发现并修正一个仅在 Linux
`with_ebpf` tagged test 才会编译到的地址 fixture 错误，修正后的全局 run
包含完整 tagged 单测、竞态、vet、BTF/对象和 Zig 交叉构建结果。
