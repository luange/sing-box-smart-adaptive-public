# sing-box Smart eBPF Data Plane v3 设计方案

> 目标读者：负责实现的 Grok / 工程人员  
> 基线：`luange/sing-box-smart-adaptive`，分支 `adaptive/official-v1.14.0-smart-ebpf`
> 原则：参考 dae 的架构思想，不复制其 AGPL 源码；保持本项目独立实现和现有 ABI 可迁移。

## 1. 目标

v3 不是再堆一组开关，而是把透明代理明确拆成两个平面：

- **控制面（Go/userspace）**：执行完整 sing-box route/rule-set/sniff/FakeIP/DNS/Smart 逻辑，产生可审计 verdict。
- **数据面（TC/cgroup eBPF）**：只执行已经编译或学习完成的 verdict；能确定 DIRECT 的流量直接走 Linux 路由，必须代理的流量送入透明监听 socket。

用户可感知目标：

1. 静态 DIRECT 规则首包即走内核，不进入 sing-box 用户态。
2. 复杂规则第一次由控制面判定，后续同一连接立即走内核 fast path。
3. DNS 学习只能作为有边界的弱提示，不能把共享 CDN 永久误判为 DIRECT。
4. 代理流量仍由 sing-box/Smart 处理；eBPF 不参与代理节点选择，不复制 Smart 状态机。
5. 任何解析失败、map miss、generation 不一致都必须回到代理/控制面，而不是错误直连。
6. 不以 AF_XDP 替代 TC。TC 负责路由分流；AF_XDP 仅保留为未来独立实验，不作为 v3 前提。

## 2. 必须先纠正的认知

### 2.1 哪些可以真正首包内核判定

可以：

- 源/目的 CIDR。
- IPv4/IPv6、TCP/UDP、源/目的端口。
- LAN 源 MAC、入口 ifindex。
- 已编译的 UID/cgroup 身份（仅本机流量）。
- DHCP、ND、广播、多播、本机管理地址等安全规则。

不能在首个数据包上天然做到：

- 尚未出现可信 DNS 关联的域名规则（v3 可嗅探明文 UDP/53 应答，再由用户态
  完整规则判定后晋升；DoH/DoT、加密 DNS 和无关联首包仍回控制面）。
- TLS/HTTP sniff 后才能知道的服务族。
- FakeIP 反向映射尚未以当前 generation 发布到内核的流量。
- 依赖完整 sing-box rule-set 组合、logical rule 或动态 provider 状态的规则。

这些流量必须先进入控制面一次。控制面判定后，才允许发布 exact-flow verdict。

### 2.2 DIRECT fast path 与代理加速不是一回事

- DIRECT：TC 返回放行，Linux 像普通路由器一样转发；这是收益最大的路径。
- PROXY：TC 通过 `bpf_sk_assign`/socket lookup 把包交给透明监听；协议握手、加密和 Smart 选择仍在用户态。
- SOCKMAP splice：只能用于语义完全等价的已建立 TCP socket 对；不得越过 TLS/AEAD/流量统计/半关闭语义。

## 3. 总体架构

```text
Provider / rule-set / DNS / FakeIP / route reload
                    │
                    ▼
       Go Policy Compiler + Verdict Publisher
                    │
      ┌─────────────┼──────────────────┐
      ▼             ▼                  ▼
 Static Policy   Exact Flow        Weak DNS/IP
 double buffer   verdict LRU       association cache
      └─────────────┼──────────────────┘
                    ▼
             TC ingress v3
                    │
       ┌────────────┴─────────────┐
       ▼                          ▼
 DIRECT / BYPASS             NEED_USERSPACE
 Linux L3 forwarding         bpf_sk_assign → sing-box
                                      │
                           route + Smart + protocol dial
                                      │
                           publish exact verdict/result
```

### 3.1 Hook 分工

| Hook | 职责 | 不允许承担 |
|---|---|---|
| TC ingress | LAN 转发流量解析、静态规则、flow verdict、socket assign | 域名 sniff、Smart 选节点 |
| TC egress | 仅必要的回程元数据恢复和统计 | 再做一次完整路由 |
| cgroup/connect4/6 | 本机 TCP 身份、connect verdict | LAN pname 推断 |
| cgroup/sendmsg4/6 | 本机 UDP 身份、UDP verdict | 为转发流量虚构 UID |
| sock_release | 清理 socket-cookie 关联 | 扫描全表 |
| sk_skb/sk_msg | 可选 TCP splice | 代理加密流量绕过用户态 |

## 4. 单一 verdict 模型

所有规则最终只能产生以下结果：

```c
enum sb_v3_verdict {
    SB_V3_UNSEEN = 0,       // 没有结论，交控制面
    SB_V3_DIRECT = 1,       // 可直接走 Linux 路由
    SB_V3_PROXY = 2,        // 必须交透明监听
    SB_V3_BLOCK = 3,        // 明确丢弃
    SB_V3_MUST_CONTROL = 4, // 永远不学习 fast path
};
```

每条 verdict 必须带：

- `policy_generation`
- `expires_ns`
- `source`：static / exact-flow / dns-weak / fakeip / control
- `confidence`
- `reason_code`
- `policy_id`

日志只输出 reason code、计数、IP 前缀或哈希；不得输出查询参数、token、订阅凭据。

## 5. TC ingress 判定顺序

顺序必须固定，并由单测锁死：

1. **解析 L2/L3/L4**：支持 VLAN（最多两层）、IPv4 options、IPv6 extension header 的有界解析。
2. **安全 bypass**：ARP、ND、DHCP、广播/多播、宿主管理地址、明确的控制面源地址。
3. **明确 BLOCK**：仅用户显式配置；`UDP/443` 不得默认 drop。
4. **静态五元组/CIDR 规则**：可首包 DIRECT/PROXY/BLOCK。
5. **exact-flow verdict**：命中 generation、TTL 和方向后执行。
6. **FakeIP 映射**：只做 map lookup；真正域名规则仍由控制面编译后的 policy id 决定。
7. **DNS 弱关联**：只有满足第 8 节资格时才可 DIRECT。
8. **既有 socket/established 路径**：合法 socket assign 或已确认直连。
9. **默认 NEED_USERSPACE**：可解析的 IP/TCP/UDP miss 送入 sing-box，而不是猜测 DIRECT。无法得到可靠五元组的截断或非 IP 帧不做 socket assign，保持无 mark 交给内核处理。

任何 verifier 边界、可解析包的 header 解析失败、map 错误、过期条目均走第 9 步；不可解析帧不伪造五元组，直接无 mark 交给内核。

## 6. Map 与 ABI

### 6.1 必需 maps

| Map | 类型 | 用途 |
|---|---|---|
| `v3_control` | ARRAY[1] | active bank、generation、功能位、监听 socket id |
| `v3_policy4/6_bank0/1` | LPM_TRIE | 双缓冲 CIDR verdict |
| `v3_port_rules_bank0/1` | ARRAY/HASH | 编译后的有界端口段规则 |
| `v3_source_policy` | HASH/LPM | ifindex + source CIDR/MAC → policy id |
| `v3_flow_verdict` | LRU_HASH | 双向 exact five-tuple verdict |
| `v3_dns_ip_hint` | LRU_HASH | DNS/FakeIP 弱关联、冲突数和 TTL |
| `v3_dns_observe` | LRU_HASH (4096) | TC 仅观察明文 DNS 应答；用户态限量排空并按完整域名规则决定是否晋升 |
| `v3_listener_sockets` | SOCKMAP | TCP4/UDP4/TCP6/UDP6 透明 listener |
| `v3_socket_identity` | LRU_HASH | cookie → UID/cgroup/process class，仅本机 |
| `v3_stats` | PERCPU_ARRAY[1] | one 32-counter vector per possible CPU; userspace aggregates |
| `v3_events` | RINGBUF | 低频异常与采样事件，不传 payload |

### 6.2 ABI 规则

- BTF map 声明和 CO-RE；禁止重新引入 legacy `bpf_map_def`。
- C/Go 结构必须 `_Static_assert` 大小和 offset，并有 Go ABI 测试。
- `abi_version`、`policy_generation` 独立；ABI 不兼容必须拒绝热接管。
- 所有 key/value 显式 padding、固定字节序。
- map capacity 必须配置化并 clamp；不得随节点数无界增长。

## 7. 控制面事务模型

### 7.1 双缓冲发布

1. 读取完整 sing-box 路由配置。
2. 将能安全下沉的规则编译到 inactive bank。
3. 校验条目数、冲突、默认 verdict 和回环保护。
4. 原子切换 `active_bank + generation`。
5. 旧 exact-flow 因 generation 不匹配自动失效。
6. 延迟清理旧 bank，避免 reload 窗口无规则。

不得逐条原地改 active map；否则 reload 中间态会造成间歇性误路由。

### 7.2 规则下沉资格

可以下沉：

- 最终结果明确且没有 sniff、domain、provider runtime、Smart 依赖的静态规则。
- private/CN CIDR 等 rule-set 已解析出的不可变 IP 前缀。
- 明确的 source CIDR/MAC + L4 + port 组合。

不得下沉：

- `domain*` 尚无可信 DNS/FakeIP 绑定。
- 结果是 selector/Smart/代理组。
- 依赖网络类型、Wi-Fi SSID 或动态接口但内核 key 未携带该身份。
- 共享 CDN IP 上存在 DIRECT/PROXY 冲突。

## 8. DNS 与域名关联

### 8.1 三类证据

1. **FakeIP authoritative**：FakeIP → domain/policy，一对一且 generation 一致，可直接用于 exact-flow 决策。
2. **DNS observed strong**：本机解析器看到 A/AAAA，答案在 TTL 内且该 IP 只对应同 verdict 的域名。
3. **DNS weak**：IP 可能属于共享 CDN，只能作为候选；首次数据流仍进控制面。

### 8.2 冲突隔离

`v3_dns_ip_hint` value 至少记录：

- `direct_refs`
- `proxy_refs`
- `policy_id`
- `expires_ns`
- `last_seen_ns`

只在 `direct_refs > 0 && proxy_refs == 0` 时允许 IP-level DIRECT。出现冲突立即降为 `MUST_CONTROL`，不能“最后写入者获胜”。

### 8.3 DNS 数据路径

- 指定 DNS 服务器 `:53` 内核直通只是一项显式策略，不等同于所有 DNS 绕过控制面。
- 需要域名 PBR 时，DNS 回答必须被控制面或可信 DNS observer 看见。
- DNS coalescing、缓存和 UDP socket 复用留在用户态 DNS 模块，不在 TC 复制 DNS parser。
- TC 只消费已经发布且未过期、无 DIRECT/PROXY 冲突的关联结果；v3 的
  `v3_dns_observe` 仅是有界、只读的提示队列，解析失败一律回控制面。

## 9. Exact-flow 学习

当 userspace 完整 route 得到最终叶子：

- 只有叶子是 `direct` 或等价的裸路由出口，才发布 `DIRECT`。
- selector/Smart 即使当前碰巧选择 direct，也不能把组永久发布为 DIRECT。
- 同时发布正向和反向 key；UDP 必须包含方向和 timeout class。
- TCP 建议 TTL 5–30 分钟，并由 FIN/RST/socket release 提前清理。
- UDP 建议按 DNS、QUIC、普通 data 分级 TTL，不共享一个长 TTL。
- 一次真实代理/路由失败必须撤销对应 flow verdict，不得扩大为整个 endpoint/IP 失败。

## 10. socket assign 与透明代理

- `socket_assign` 保持默认，token 只作显式兼容模式。
- listener 不存在、协议不匹配、assign helper 失败时：
  - 普通流量 fail-open 到现有透明代理 fallback；
  - 不能直接放行到公网，避免策略泄漏。
- mark 只在确定 handoff 成功的分支设置；bypass/drop/parse-fail 不得污染 mark。
- 管理网、SSH 和回滚通道必须拥有最高优先级安全 bypass。
- 不允许每包创建用户态 UDP session；只有 NEED_USERSPACE 的 UDP 才进入 sing-box NAT。

## 11. TCP splice 的定位

保留为可选模块，默认关闭，只有全部条件满足才启用：

- 两端 socket 已建立。
- outbound 类型在显式白名单。
- 不需要 TLS/AEAD/压缩/协议 framing。
- 不需要用户态 payload sniff、限速或逐包统计。
- 半关闭语义已经通过测试。

DIRECT 流量已经由 TC 直接路由，不需要再 splice。不要为了表面上的“全内核”把代理协议错误绕过。

## 12. Smart 的边界

eBPF v3 不实现 Smart，只向 Smart 提供干净输入：

- Smart 节点画像由固定 204、真实连接成功/失败、RTT EWMA 和 jitter 维护。
- eBPF 不读取节点名、权重、EndpointProfile 或服务族。
- Smart 选择变化只影响后续代理连接；健康节点性能切换不杀已有连接。
- 节点确认死亡时，Smart 自己决定故障切换；eBPF 只按 socket/flow 生命周期清理。

这样避免形成两套互相冲突的健康状态机。

## 13. 配置草案

```json
{
  "type": "ebpf",
  "tag": "PA-in",
  "capture_local": false,
  "network": ["tcp", "udp"],
  "dns_mode": "hijack",
  "shared_network": {
    "enabled": true,
    "engine": "v3",
    "include_interface": ["pa-hk", "pa-us", "pa-jp", "pa-sg", "pa-other"],
    "data_plane": "socket_assign",
    "policy_offload": {
      "enabled": true,
      "static_rules": true,
      "exact_flow_learning": true,
      "dns_ip_hint": "safe",
      "fakeip": true,
      "mac_source_policy": true
    },
    "failure_mode": "proxy",
    "drop_udp_443": false
  },
  "outbound_offload": {
    "splice": { "enabled": false },
    "verdict": {
      "mode": "learn",
      "ttl": "5m",
      "max_entries": 8192,
      "promote_bypass": false
    }
  }
}
```

兼容策略：

- 未写 `engine` 继续使用当前 v2。
- v3 首期必须显式 `engine: v3`，验证完成后才考虑默认。
- 旧字段映射必须集中在 config migration，不在数据面保留重复实现。

## 14. 可观测性

必须按 reason 分开计数：

- `static_direct`
- `flow_direct`
- `fakeip_direct`
- `dns_hint_direct`
- `policy_proxy`
- `map_miss_proxy`
- `generation_miss_proxy`
- `parse_fail_proxy`
- `socket_assign_success/failure`
- `blocked`
- `dns_hint_conflict`
- `map_capacity_reject`

同时输出：

- map 当前条目/上限。
- 每秒 DIRECT/PROXY/BLOCK 包与字节。
- 用户态避免创建的 TCP/UDP session 数。
- ringbuf drop。
- reload generation 与耗时。

周期日志只输出 delta 和峰值，不能每包打印。

## 15. 故障与安全边界

| 故障 | 正确行为 |
|---|---|
| policy map 未加载 | 全部回控制面，管理网保持可达 |
| generation 不匹配 | 不执行旧 verdict |
| DNS IP 冲突 | MUST_CONTROL |
| listener socket 丢失 | 报警并走受控 fallback，不裸直连 |
| ringbuf 满 | 丢观测事件，不丢业务包 |
| LRU eviction | 下次回控制面重学，不复用残缺状态 |
| reload 中断 | active bank 不变 |
| TC detach | Linux 原始路由恢复，不留下 mark/rule 黑洞 |

## 16. 实现分期

### Phase A：统一 verdict ABI

- 新建 `common/ebpf/v3/abi.h` 与 Go mirror。
- generation、source、reason、expiry 统一。
- 完成 ABI/static assert、endianness 和 map capacity 测试。

### Phase B：静态首包 fast path

- 双 bank LPM/port/source policy compiler。
- TC v3 固定判定顺序。
- IPv4/IPv6、TCP/UDP 对称实现。
- 先只支持能证明等价的规则子集。

### Phase C：exact-flow learn

- userspace route 完成后发布双向 flow verdict。
- generation reload 失效。
- TCP FIN/RST、UDP 分级 TTL、LRU eviction 验证。

### Phase D：DNS/FakeIP 安全关联

- FakeIP authoritative map。
- DNS strong/weak 与冲突计数。
- CDN 共 IP 反例测试。

### Phase E：可选能力

- source MAC policy。
- 本机 UID/cgroup identity。
- 受限 TCP splice。
- AF_XDP probe 仅做实验数据，不进入生产路径。

## 17. 测试矩阵

### 17.1 单元/模型测试

- 规则编译顺序与反例。
- v4/v6、TCP/UDP 完全对称。
- 双 bank 切换原子性。
- DNS shared-IP DIRECT/PROXY 冲突不得直通。
- generation rollover。
- map 满、LRU eviction、过期。
- mark 污染：所有 bypass/failure 分支 mark 必须为 0。

### 17.2 真内核 verifier 测试

- Debian 当前 PVE kernel。
- 至少一个较旧 LTS 和一个较新 kernel。
- amd64/arm64。
- committed `.o` 必须实际 load；禁止只测重新生成产物。

### 17.3 网络命名空间集成测试

拓扑：client ns → gateway ns → origin/proxy ns。

验证：

- 静态 DIRECT 首包不触发 userspace accept。
- 未知流首包进入 userspace，第二条同 verdict flow 命中内核。
- DIRECT 回程正确、MTU/fragment/PMTU 正确。
- UDP DNS、普通 UDP、QUIC 分开。
- reload 1000 次不丢管理连接、不留下旧 generation。

### 17.4 117 canary

- 不直接上 115。
- 比较 v2/v3：RSS、HeapAlloc、goroutine、FD、软中断、CPU、p50/p95/p99 RTT。
- 统计真正避免的 userspace sessions，而不是只看总吞吐。
- 故障注入：listener 消失、map 满、provider reload、TC detach、DNS 冲突。

### 17.5 生产门槛

- 117 通过后才上 115。
- 115 先单地区/单源地址 canary，再扩大。
- 真实 Google 204 连续成功；不恢复 YouTube/GoogleVideo watchdog。
- 任何 SSH/管理网异常、策略泄漏、panic、单调内存增长立即停止扩大。

## 18. 性能验收指标

以相同硬件、相同规则、相同流量回放比较 v2：

- 静态 DIRECT userspace session 创建数下降至少 95%。
- DIRECT 吞吐不低于纯 Linux forwarding 的 90%。
- DIRECT p99 延迟相对纯转发增加不超过 10%。
- 代理路径 p95 不劣化超过 5%。
- 空闲 RSS 不因 map capacity 线性预分配大幅增加。
- 10k 并发下无 map 无界增长、无 goroutine/session 与 DIRECT 流量等比例增长。
- reload 后旧 generation 命中数必须为 0。

## 19. 代码组织建议

```text
common/ebpf/v3/
  abi.h
  parser.h
  policy_maps.h
  tc_ingress.bpf.c
  tc_egress.bpf.c
  cgroup.bpf.c
  loader.c
  runtime.c

protocol/ebpf/v3/
  compiler.go
  publisher.go
  dns_hint.go
  fakeip.go
  lifecycle.go
  metrics.go
  migration.go
```

不要继续把 v3 分支塞进 `shared_network_v2.bpf.c` 的大量条件判断中。v2 保持可回滚；v3 共享稳定的 loader/ABI 工具，但拥有独立程序和测试。

## 20. 给实现者的硬性约束

1. 不复制 dae 源码；只借鉴“TC 提前分流、DIRECT 走内核”的架构原则。
2. 不把域名能力伪装成首包能力。
3. 不把 DNS IP 提示当成永久事实。
4. 不默认 drop QUIC。
5. 不让 eBPF 参与 Smart 节点选择。
6. 不用 AF_XDP 解决本应由 TC 路由解决的问题。
7. 不以“verifier 能加载”代替数据面正确性测试。
8. 不允许 map miss 时错误直连。
9. 不允许 reload 原地逐条更新 active policy。
10. 所有代码完成后先部署 117；通过门槛前不得推 115/107。
