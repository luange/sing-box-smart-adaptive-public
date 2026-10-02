# sing-box v1.14.0 正式版打包记录

## 基线

- 上游正式标签：`v1.14.0`
- 上游提交：`0b8995879f29a9b98ee027bc17b75e101445b238`
- 集成提交：`f9b92115773f779720fd02353ee6b5b8b17db70b`（保留本项目 Smart、Smart Zig、eBPF v3、provider、
  connection-history、Clash/Zashboard API 与 PBR 适配）
- 发布分支：`adaptive/official-v1.14.0-smart-ebpf`

## 构建配置

正式版通过 GitHub Actions 在 Ubuntu Linux 上构建，不在 macOS 本地编译。网关
精简标签仅包含当前部署需要的 gVisor、QUIC、DHCP、WireGuard、uTLS、Clash API、
connection-history、Tailscale、eBPF v3 与 Smart Zig；musl 产物为静态链接。
目标矩阵为 amd64/arm64 × glibc/musl。

发布前门禁包括：提交的 eBPF v2 provenance、Linux 重新生成、Smart Zig 单测与 C ABI、
Smart/传输回归测试，以及 amd64 glibc 的配置检查。eBPF 对象必须先通过 provenance
检查后才允许进入打包步骤，防止源码与 `go:embed` 对象漂移。

## 运行边界与部署记录

正式版产物已在 Linux CI 完成四架构构建并核对校验码。2026-09-03 的初始正式版
部署曾同时验证 VM107/VM115；随后按生产变更范围，VM107 保持原二进制不动，VM115
单独接受深审修复后的原子替换。

- VM107：继续运行 Revision `f9b92115773f779720fd02353ee6b5b8b17db70b`，SHA-256
  `9550a73d428be2d37a62218f6ac12417c66114fb82cd2ec488d39fdd3b99e766`，tproxy 入站。
- VM115：运行 Revision `80756e692b186b09bbf4f9c869cd0885a7991d45`，SHA-256
  `d88fa5fcfdf40d2b68b940c5265182185f70b233aa6b0a48bdb597c9e6a49a67`，eBPF v3
  `socket_assign`。

VM115 替换前通过资产校验与配置检查，替换后通过服务启动、9091 API、监听端口和
错误日志门禁；VM107 本轮未执行写操作。
