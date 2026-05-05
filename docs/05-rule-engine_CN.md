# 规则引擎与威胁检测

engine 负责把原始日志转换成可展示、可处置的威胁活动和威胁事件。它消费 Redis 日志队列，先做单事件 Sigma 匹配，再做多事件 Flow 关联。

## 启动入口

入口文件：

- `engine/cmd/engine.go`
- `engine/config/config.go`
- `engine/core/core.go`
- `engine/core/match.go`

启动过程：

1. 从 `ENGINE_CONF_PATH` 或 `./engine.yaml` 加载 Redis、MongoDB、ES 和日志配置。
2. 从 `/home/adadmin/rules/flow` 加载 Flow 规则。
3. 从 `/home/adadmin/rules/winlog` 加载 winlog Sigma 规则。
4. 从 `/home/adadmin/rules/pktlog` 加载 pktlog Sigma 规则。
5. 将 Flow 关联的 Sigma 字段映射缓存到 Redis。
6. 确保 `ada-activity` ES index 存在。
7. 启动规则 reload 监听、FlowMatcher、FlowCleaner 和 SigmaMatcher。

## 检测链路

```mermaid
flowchart LR
  RedisQueue[Redis: ada:evelog_queue / ada:pktlog_queue]
  Sigma[SigmaMatcher]
  Activity[AlertActivity]
  FlowCache[Redis flow instance/cache]
  FlowMatcher[FlowMatcher]
  Threat[AlertEvent]
  Mongo[(MongoDB)]
  ES[(Elasticsearch)]

  RedisQueue -->|BRPOP| Sigma
  Sigma -->|single event match| Activity
  Activity --> Mongo
  Activity --> ES
  Activity --> FlowCache
  FlowCache --> FlowMatcher
  FlowMatcher -->|correlation match| Threat
  Threat --> Mongo
  Threat --> RedisNotify["Redis: ada:server:notify_queue"]
```

## Sigma 单事件规则

规则目录：

- `engine/rules/winlog`
- `engine/rules/pktlog`

规则字段由 `engine/sigma/rule.go` 定义，核心字段包括：

| 字段 | 说明 |
| --- | --- |
| `id` | 规则 ID，winlog/pktlog 规则应保持唯一 |
| `title` | 规则标题 |
| `description` | 规则描述 |
| `level` | 风险等级，支持 `info/low/medium/high/critical` 或 `1..5` |
| `tags` | ATT&CK 等标签，至少需要一个 |
| `logsource` | 日志来源 |
| `detection` | Sigma detection 表达式 |
| `fields` | 命中后提取字段 |
| `unique_fields` | 生成 `unique_id` 的字段 |
| `rdx_key` | 内置规则缓存 key，可用于给后续规则提供上下文 |

完整 YAML 编写语法、示例、验证步骤和排查方法见 [Engine YAML 规则开发指南](../engine/RULE_GUIDE_CN.md)。

匹配输出：

- 命中后生成 `AlertActivityESDB`。
- 写入 MongoDB collection `tb_alert_activity`。
- 以 MongoDB ObjectID 作为 ES doc id 写入 `ada-activity`。
- 如果规则关联 Flow，则把 activity 元信息写入 Redis flow cache。

## Flow 多事件关联规则

规则目录：

- `engine/rules/flow`

Flow 规则支持的事件类型：

| 类型 | 说明 |
| --- | --- |
| `count` | 同一窗口内同类 activity 达到次数阈值 |
| `multi_eve` | 多条 eventlog activity 关联 |
| `multi_pkt` | 多条 pktlog activity 关联 |
| `multi_eve_pkt` | eventlog 和 pktlog 混合关联 |

Flow source 校验是强约束：

- `multi_eve` 只能引用 `winlog-*` Sigma 规则。
- `multi_pkt` 只能引用 `pktlog-*` Sigma 规则。
- `multi_eve_pkt` 必须同时引用 `winlog-*` 和 `pktlog-*` Sigma 规则。

核心 Redis key：

- `ada:engine:flow_rule_map`：sigma rule id 到 flow id 的映射。
- `ada:engine:flow_field_map`：flow id 到可用于白名单/展示的字段集合。
- `ada:engine:instance:<flow_id>_<instance_key>`：Flow instance 的 activity zset。配置 Flow `cache_key` 时使用归一化后的 instance key，否则兼容使用 Sigma `unique_id`。
- `ada:engine:active:<flow_id>`：活跃 Flow instance 集合，避免全量 `KEYS` 扫描。
- `ada:engine:activity_cache:<mongo_id>`：activity 元信息缓存。
- `ada:engine:ldap_search_channel`：`$v.ldap` cache miss 后的异步查询通道。
- `ada:engine:ldap_search_pending:<hash>`：`$v.ldap` miss 去重 key，默认 TTL 60s。

Flow 生命周期：

1. Sigma 命中 activity。
2. engine 查询 `flow_rule_map`，判断该 Sigma 是否参与某个 Flow。
3. 如果参与，将 activity 写入对应 Flow instance zset。Flow `cache_key` 可归一化 domain、username、IP 等字段，让 winlog/pktlog activity 进入同一个 instance。
4. `FlowMatcher` 每秒扫描活跃 instance。
5. 匹配成功后生成 `AlertEventESDB`，写入 `tb_alert_event`，并推送 Redis notify。
6. `FlowCleaner` 每 2 分钟清理超出窗口的 activity cache 和 zset member。

### Flow `match_by`

`match_by` 已从 `AND` 字符串切分升级为 AST 解析，支持：

- 布尔操作符：`AND`、`OR`、`NOT`。
- 括号，默认优先级为 `NOT > AND > OR`。
- 叶子操作符：`== != > >= < <= in`。
- `$v.cache.key_...(...)` 和 `$v.ldap.key_...(...)` 查询模板。

示例：

```yaml
match_by: "($s1.UserName == $s2.TargetUserName OR $s1.UserSid == $s2.TargetUserSid) AND NOT ($s1.TargetDomainName == blocked)"
```

### Count 规则

`count` Flow 支持以下写法：

```yaml
match_by: "$s1._count >= 5"
match_by: "len($s1) >= 5"
match_by: "len(distinct($s1.TargetUserName)) >= 3"
match_by: "$s1.TargetUserName._count >= 3"
```

`len(distinct($s1.Field))` 和 `$s1.Field._count` 统计字段去重值数量，比较前会 `trim + lower`；所有 count 写法都支持 `== != > >= < <=`。

### `$v.ldap` 查询

`$v.ldap` 避免在 FlowMatcher 热路径里阻塞 LDAP：

1. FlowMatcher 生成 Redis set key 并执行 `SMEMBERS`。
2. set 命中时同步完成匹配。
3. set 缺失或为空时，engine 写入 `ada:engine:ldap_search_pending:<hash>`，TTL 60s，并向 `ada:engine:ldap_search_channel` 发布 JSON 查询请求。
4. tasker 收到请求后读取域 LDAP 账号，异步查询 LDAP，并用 60s TTL 写回 Redis set。

当前 LDAP-backed set 支持 `sensitive_users`、`sensitive_groups` 和 `sensitive_computers`。`honeypot_accounts` 保持手动或预填充缓存。

### ES Bulk Writer

`core.ESIndexer` 批量写入 activity 到 `ada-activity`。现在 bulk 请求失败会最多重试 3 次并使用指数退避；重试耗尽后丢弃该批次，并记录 `ESIndexerStats`：

- `EnqueuedItems`
- `FlushBatches`
- `IndexedItems`
- `RetryAttempts`
- `FailedBatches`
- `DroppedItems`
- `LastError`

## 规则热加载

热加载触发方式：

- 发送 `SIGHUP` 到 engine 进程。
- 向 Redis pubsub channel `ada:engine:reload` 发布 reload 消息。

热加载会重新读取：

- Flow 规则
- winlog Sigma 规则
- pktlog Sigma 规则

然后原子替换内存中的 ruleset，并刷新 Redis 中的规则字段缓存。

## 常见排查路径

1. 检查 `ada:evelog_queue` 和 `ada:pktlog_queue` 是否有日志进入。
2. 检查 engine 日志中是否加载 winlog、pktlog、flow ruleset。
3. 检查 `tb_alert_activity` 是否新增记录。
4. 检查 `ada-activity` 是否新增文档。
5. 如果只有 activity 没有 event，检查 `ada:engine:flow_rule_map` 和 Flow instance key。
6. 如果使用 `$v.ldap`，检查 Redis lookup set、`ada:engine:ldap_search_pending:<hash>` 和 tasker 中 `ada:engine:ldap_search_channel` 的处理日志。
7. 如果 ES 写入滞后，检查 ES bulk retry 日志和 `ESIndexerStats`。
8. 如果规则刚修改，确认是否触发 `ada:engine:reload` 或重启 engine。
