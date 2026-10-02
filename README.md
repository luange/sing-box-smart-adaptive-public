# sing-box-smart-adaptive

基于 **[SagerNet/sing-box](https://github.com/SagerNet/sing-box)** 官方 1.14 稳定线(基线 `v1.14.9` 之后,当前发布 `v1.14.x`)的定制核心。

**策略：纯官方基底 + 自有一等公民能力，不做 reF1nd 整树覆盖。**

| | |
|--|--|
| **当前线** | `adaptive/official-v1.14.0-smart-ebpf`(官方 1.14 稳定线) |
| **版本串** | `1.14.x-official-smart-ebpf`(当前 v1.14.15) |
| **上游** | [SagerNet/sing-box](https://github.com/SagerNet/sing-box) |
| **许可** | GPL-3.0（同上游） |

官方文档：https://sing-box.sagernet.org  

本仓库增量说明见下方与 [docs/ports/OFFICIAL-BASE.md](docs/ports/OFFICIAL-BASE.md)、[CHANGELOG.adaptive.md](CHANGELOG.adaptive.md)。

---

## 相对官方多了什么

### 1. Smart 出站组（`type: smart`）

- 多候选 / provider 展开、评分、粘性、半开熔断、探测共享 registry  
- **PreMatch**：透明路径只读稳定 leaf，不推进 hedge/retry  
- HA：Close 有界等待，探测不阻塞重启  
- 探测路径无强制 `runtime.GC()`，冷启动探测默认 cap 45s  

### 2. eBPF 网关（`type: ebpf`，`with_ebpf`）

面向 **PBR + shared_network**（TC 接管网卡），不是 reF1nd cilium 整栈。

| 能力 | 说明 |
|------|------|
| **shared_network** | TC `socket_assign`，多网卡 include |
| **bypass_rule_set** | 静态 geoip 等 LPM，国内直连在内核卸掉 |
| **dns_prefill** | DNS A/AAAA → 稳定 DIRECT 时 TC `/32` promote |
| **flow_verdict** | 精确流直连（需 verdict learn） |
| **verdict learn** | 用户态 empty DIRECT dial 后写 map（PBR 下代理热路径多为 non_direct） |
| **DirectOffload** | 路由选 DIRECT 时 promote（hub 多 inbound） |
| **splice** | sockmap 可选；默认关；明文叶子（direct/socks/http）才有意义 |
| **bypass miss 抽样** | 每 N 条进 userspace 对照 LPM；kernel_miss 告警；DIRECT 漏表可 gap_heal |

**Hub 模型**（多 eBPF inbound 安全）：  
`DirectOffload` / `DNSAnswerObserver` / `VerdictLearner` / `ConnectionSplicer` 均为 fan-out hub，在 `box.New` 注册。

### 3. Provider

- remote / local / inline  
- Clash 订阅解析（字段子集；不支持的 warn 一次）  
- 重复节点名 **内容稳定** 后缀 `#`+hex（避免 `(2)` 顺序漂移弄坏 pin）  

### 4. 其它出站

- `loadbalance`、`pass`、`adaptive_pool`（注册完整；adaptive **故意** `PreMatchDisabled`）  

### 5. Connection history（`with_connection_history`）

- Clash API：`GET /history`、`/summary`、`/connections`…  
- 关闭时 `FinalizeChain`：记 **真实叶子**（如 `airport/…` + `HK`），不是只有组 tag  
- 关闭记录包含 `closeReason`（`client_eof`、`remote_eof`、`remote_rst`、`dial_timeout`、`handshake_timeout`、`idle_timeout` 等），用于区分正常短连接与真正失败。
- SBH2 使用无 mmap 的 Zstd 不可变分段：明细默认 6h、聚合按配置保留，默认硬上限 256 MiB。
- 活跃长连接每分钟 checkpoint；建立、关闭、失败及 Smart 切换仍走即时事件，不再每 5 秒全量写库。

---

## 逻辑闭环（必须同时成立）

```
route MatchInputs（含 RuleSet MatchClass）
  → NoteRoutedDirect / dns_prefill → TC bypass
dial 成功 → VerdictLearnerHub + ConnectionSplicerHub
group 选叶 → NoteRealOutbound → history FinalizeChain
多 inbound → 四个 Hub Add/Remove
```

PBR 场景下：**进进程的几乎全是代理**；CN 靠 **TC 静态 bypass + dns_prefill**，不是 dial learn writes。

---

## 构建

```bash
# Linux amd64 + eBPF + history（与 115 生产 tags 对齐）
TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_connection_history,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_usbip,with_openvpn,with_openconnect,with_ebpf"

CGO_ENABLED=1 go build -tags "$TAGS" -trimpath \
  -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.15" \
  -o sing-box ./cmd/sing-box
```

- 完整 eBPF 产物通常 **>50MB**  
- 需要 Linux + CGO + 内核 BTF/TC 能力  

辅助脚本：

```bash
# 网关历史目的地抽样（对照是否该直连）
sh scripts/bypass-miss-sample.sh 50
```

---

## 远程与上游

| remote | 用途 |
|--------|------|
| `origin` | 本仓库 `luange/sing-box-smart-adaptive` |
| `sagernet` | 官方上游（可选 `git fetch sagernet`） |

**不再跟踪 reF1nd 远程**；不合并其整树 eBPF overlay。

客户端 submodule（`clients/apple|android|desktop`）为上游官方客户端工程，**仅官方 CI/打包需要**；纯网关二进制构建可忽略：

```bash
git clone --depth 1 https://github.com/luange/sing-box-smart-adaptive.git
# 不必 submodule update，除非你要编官方 GUI 客户端
```

---

## 分支建议

| 分支 | 说明 |
|------|------|
| `adaptive/official-v1.14.0-smart-ebpf` | **当前推荐**（官方 1.14 稳定线 + 自有能力） |
| `main` | 与推荐线同步（推送后） |

---

## 许可

同 SagerNet sing-box（GPL-3.0）。衍生作品命名与关联限制见上游 LICENSE。  
本仓库为个人/运维定制，**非** SagerNet 官方产品。
