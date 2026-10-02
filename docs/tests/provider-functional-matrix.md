# Provider 组合实验测试矩阵

这组测试用于验证多订阅组合、重名节点和动态刷新；只验证功能闭环，不把结果表述为性能基准。测试环境使用隔离 VM117，生产 VM107/115 不改配置。

## 固定输入

从 NAS SubStore 临时读取两个独立源 `xsus1`、`xsus2`，只在测试进程内存中使用响应，不把 URL、查询参数、凭据或订阅内容写入仓库。两源都应能解析为节点列表，并保留原始显示名。

## 用例与验收

| 编号 | 组合 | 验收条件 |
|---|---|---|
| P1 | 单 provider + `include` | 仅匹配节点进入组；启动无 `missing tags`/`tag not found`。 |
| P2 | 两 provider + 同名节点 | 所有成员保留；显示名稳定为原名、`#2`、`#3`；重排源顺序不会更换 endpoint identity。 |
| P3 | `use_all_providers` | 新增/删除 provider 通过回调反映；删除成员不出现在 `All()`，也不能再被拨号。 |
| P4 | provider-only selector/urltest/loadbalance | `outbounds` 为空但 provider 有效时可启动、可列出成员并可选择/测速。 |
| P5 | 删除当前选中成员 | selector 自动回退 default/首个可用成员；旧对象不再被调用。 |
| P6 | 同步回调与关闭竞态 | provider 在注册回调时立即通知不会死锁；关闭后迟到回调无效且所有句柄注销。 |
| P7 | tag miss | 不存在的显式 provider 返回带索引和 tag 的错误；不会留下半发布 membership。 |
| P8 | 过滤与重复刷新 | `include/exclude` 在缓存和刷新路径一致；未变化 provider 不重复调用 `Outbounds()`。 |
| P9 | 聚合 provider + 单 provider 并存 | `type: aggregate` 的组合可被任意组引用；源 provider 仍可单独引用；源更新/删除会实时反映，重名节点稳定加后缀。 |
| P10 | 混合/精简构建协议过滤 | 未注册协议、缺少 `type`、选项解析失败或空选项成员被忽略；有效成员仍保留，日志只包含 provider、序号、tag、协议和有限原因，不包含 URL/凭据。 |

## 聚合 provider 语义

聚合 provider 只保存源 provider 的 tag，不复制订阅内容、连接或健康画像。示例：

```json
{
  "providers": [
    {"type": "remote", "tag": "airport-a", "url": "https://example.invalid/a", "include": "HK|香港", "exclude": "Gcore"},
    {"type": "remote", "tag": "airport-b", "url": "https://example.invalid/b"},
    {"type": "aggregate", "tag": "airports-all", "providers": ["airport-a", "airport-b"], "include": "HK|JP"}
  ],
  "outbounds": [
    {"type": "smart", "tag": "smart-all", "providers": ["airports-all"]},
    {"type": "selector", "tag": "airport-a-only", "providers": ["airport-a"]}
  ]
}
```

源 provider 的 `include/exclude` 在其自身解析阶段执行；聚合 provider 和组级 `include/exclude` 再分别作为下一层门禁。这样既能给每个订阅单独过滤，又能保留聚合视图和单订阅视图。

为避免同一节点被聚合视图和源 provider 重复展开，组级 `use_all_providers` 只纳入叶子 provider；需要使用聚合视图时显式写入 `providers`。聚合 provider 本身仍可被 Smart、URLTest、LoadBalance 或 Selector 单独引用。

## 协议筛选语义

订阅解析先逐成员尝试（Sing-box JSON、Clash YAML、SIP-008 和 URI 列表），再使用当前构建实际注册的 outbound/endpoint 类型表作最终门禁。单个坏成员不会使整份订阅失效；当所有成员都不可解析或不在本构建中时，provider 返回明确的 `no supported servers found` 错误。协议错误按成员限频记录，避免刷新风暴污染日志；日志只保留 `provider/序号/tag/type/原因码`，不会回显订阅 URI、查询参数或凭据。接口内的 typed-nil 选项也会被门禁丢弃，防止后续具体协议覆盖逻辑崩溃。精简构建保留的 schema-only stub（例如未编译的 QUIC/Naive/WireGuard）会再经过 `IsSupported` 能力门，构造器不可用的协议不会进入组。

## 执行门

先运行：

```sh
go test ./protocol/group ./adapter/provider
go test -race ./protocol/group ./adapter/provider
go test ./provider/aggregate
```

再在 VM117 用当前 Linux 构建加载临时配置，确认 provider 组实际 `All()`、选择和删除回调；只允许使用临时端口和临时运行目录。GitHub Actions 使用 `release-linux.yml` 手动运行并将 `publish_release=false`，仅上传 Actions Artifact，不创建公开 Release。全部用例通过后才可提出生产部署申请。
