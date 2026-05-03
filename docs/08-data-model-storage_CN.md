# 数据模型与存储约定

本项目同时使用 MongoDB、Redis 和 Elasticsearch。理解三者分工是排障和开发的关键。

## 存储分工

| 存储 | 角色 | 典型内容 |
| --- | --- | --- |
| MongoDB | 业务事实库 | 用户、域、sensor、规则、扫描任务、告警、资产、通知、审计 |
| Redis | 队列和缓存 | 异步任务、日志队列、sensor 控制、规则缓存、状态统计、通知队列 |
| Elasticsearch | 检索和日志库 | eventlog、packetlog、activity、Kibana 展示数据 |

## MongoDB collections

定义文件：

- `backend/model/tables.go`
- `engine/model/types.go`

| Collection | 模型 | 说明 |
| --- | --- | --- |
| `tb_user` | `User` | 用户、角色、MFA、密码状态、活跃时间 |
| `tb_access_key` | `AccessKey` | API/MCP AccessKey |
| `tb_domain` | `Domain` | 域配置、LDAP 配置、DC 列表 |
| `tb_sensor` | `Sensor` | sensor 状态、插件开关、网卡、资源限制 |
| `tb_system_info` | `SystemInfo` | 系统名称、语言、代理、监控配置 |
| `tb_notify` | `Notify` | 消息中心 |
| `tb_notify_conf` | `NotifyConf` | 通知配置 |
| `tb_audit_log` | `AuditLog` | 操作审计 |
| `tb_system_logs` | `SystemLogs` | 系统日志查询用记录 |
| `tb_scan_plugin` | `ScanPlugin` | 主动扫描插件 |
| `tb_scan_template` | `ScanTemplate` | 主动扫描模板 |
| `tb_scan_conf` | `ScanConf` | 周期扫描计划 |
| `tb_scan_tasks` | `ScanTasks` | 扫描主任务 |
| `tb_scan_subtasks` | `ScanSubTasks` | 扫描子任务和插件结果 |
| `tb_alert_rule` | `AlertRule` | Flow/关联告警规则 |
| `tb_activity_rule` | `AlertActivityRule` | Sigma/activity 规则 |
| `tb_alert_activity` | `AlertActivityESDB` | 单事件 activity |
| `tb_alert_event` | `AlertEventESDB` | 多事件 threat event |
| `tb_alert_whitelist` | `AlertWhitelist` | 告警白名单 |
| `tb_alert_block` | `AlertBlock` | 威胁阻断 |
| `tb_sensitive_entry` | `SensitiveEntry` | 敏感用户/组/计算机/蜜罐账号 |
| `tb_asset_user` | `AssetUser` | AD 用户资产 |
| `tb_asset_group` | `AssetGroup` | AD 组资产 |
| `tb_asset_computer` | `AssetComputer` | AD 计算机资产 |
| `tb_export_task` | `ExportTask` | 报表导出任务 |

## Redis key 约定

### Sensor

| Key | 类型 | 说明 |
| --- | --- | --- |
| `ada:sensor:cmd_channel` | pubsub | 命令下发 |
| `ada:sensor:cmd_task_<task_id>` | hash | 命令结果 |
| `ada:sensor:state` | list | sensor 状态事件 |
| `ada:sensor:id:<uuid>` | hash | sensor 配置和状态 |
| `ada:sensor:latest_version` | string | 最新 sensor 版本 |
| `ada:sensor:latest_binsum` | string | 最新 sensor 二进制 hash |
| `ada:sensor:latest_binfile` | bytes | 最新 sensor 二进制 |
| `ada:sensor:collect_stats` | hash | 采集心跳，包含 winlog/pktlog 最近时间 |

### 日志和检测

| Key | 类型 | 说明 |
| --- | --- | --- |
| `ada:evelog_queue` | list | eventlog 队列，task_server 写，engine 读 |
| `ada:pktlog_queue` | list | pktlog 队列，task_server/Zeek 写，engine 读 |
| `ada:pktlog_channel` | pubsub | Zeek RedisWriter 发布 pktlog，task_server 订阅写 ES 和统计 |
| `ada:engine:reload` | pubsub | engine 规则热加载 |
| `ada:engine:flow_rule_map` | hash | Sigma rule id 到 Flow rule id 映射 |
| `ada:engine:flow_field_map` | hash | Flow rule id 到字段集合 |
| `ada:engine:instance:<flow_id>_<unique_id>` | zset | Flow instance activity 时间序列 |
| `ada:engine:active:<flow_id>` | set | 活跃 Flow instance key 集合 |
| `ada:engine:activity_cache:<mongo_id>` | hash | activity 关联缓存 |
| `ada:engine:flow_whitelist...` | hash | Flow 白名单条件 |
| `ada:server:notify_queue` | list | engine/scanner 推送通知，task_worker 消费 |

### 域和资产缓存

| Key | 类型 | 说明 |
| --- | --- | --- |
| `ada:server:domain_list` | string/set 视实现而定 | 域列表缓存 |
| `ada:server:ldap:<domain>` | string | LDAP 账号缓存 |
| `ada:server:<domain>:ip_relate_dc` | hash | IP 到 DC FQDN 映射 |
| `ada:engine:dc_ip:<ip>` | string | Zeek RedisWriter 用 IP 反查 hostname |
| `ada:engine:<domain>:sensitive_users` | set | 敏感用户 |
| `ada:engine:<domain>:sensitive_groups` | set | 敏感组 |
| `ada:engine:<domain>:sensitive_computers` | set | 敏感计算机 |
| `ada:engine:<domain>:honeypot_accounts` | set | 蜜罐账号 |

### 系统和 dashboard

| Key | 类型 | 说明 |
| --- | --- | --- |
| `ada:server:stats:info` | hash | ES、系统状态信息 |
| `ada:server:stats:load` | list | 系统 load 监控 |
| `ada:server:stats:cpu` | list | CPU 监控 |
| `ada:server:stats:mem` | list | 内存监控 |
| `ada:server:stats:net_rx` | list | 网络接收 |
| `ada:server:stats:net_tx` | list | 网络发送 |
| `ada:server:stats:cfg` | hash | 监控阈值配置 |
| `ada:server:stats:winlog:<domain>` | zset | winlog 按分钟统计 |
| `ada:server:stats:pktlog:<domain>` | zset | pktlog 按分钟统计 |

## Elasticsearch indices

| Index | 写入方 | 用途 |
| --- | --- | --- |
| `ada-eventlog-YYYY.MM.DD` | task_server | Windows eventlog 原始日志检索 |
| `ada-packetlog-YYYY.MM.DD` | task_server | pktlog 原始日志检索 |
| `ada-activity` | engine | activity 检索和告警行为展示 |

字段约定：

- 时间字段使用 `@timestamp`。
- packetlog 的 `ProtocolFields` 是对象字段且禁用索引，避免动态字段爆炸。
- engine 的 activity JSON 由 MongoDB 模型和 ES 模型共享定义，修改字段时需要同步 `backend/model/tables.go` 和 `engine/model/types.go`。

## 数据一致性注意事项

- MongoDB 是业务状态准源，ES 主要用于检索和展示，不能只看 ES 判断业务任务是否失败。
- Redis 队列是异步边界，队列积压不等于数据丢失，但长期积压说明消费者异常或 pending。
- Flow 关联依赖 Redis 缓存 TTL，超过窗口后无法再关联历史 activity。
- Zeek RedisWriter 依赖 `ada:engine:dc_ip:<ip>` 将 IP 映射为 hostname；映射缺失会影响域归属。
