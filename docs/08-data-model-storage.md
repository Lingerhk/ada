# Data Model and Storage Conventions

This project uses MongoDB, Redis, and Elasticsearch. Understanding their division of responsibilities is essential for troubleshooting and development.

## Storage Responsibilities

| Storage | Role | Typical content |
| --- | --- | --- |
| MongoDB | Business source of truth | Users, domains, sensors, rules, scan tasks, alerts, assets, notifications, audit records |
| Redis | Queues and cache | Async tasks, log queues, sensor control, rule cache, status statistics, notification queue |
| Elasticsearch | Search and log store | eventlog, packetlog, activity, Kibana display data |

## MongoDB collections

Definition files:

- `backend/model/tables.go`
- `engine/model/types.go`

| Collection | Model | Description |
| --- | --- | --- |
| `tb_user` | `User` | Users, roles, MFA, password state, active time |
| `tb_access_key` | `AccessKey` | API/MCP AccessKey |
| `tb_domain` | `Domain` | Domain configuration, LDAP configuration, DC list |
| `tb_sensor` | `Sensor` | Sensor status, plugin switches, NICs, resource limits |
| `tb_system_info` | `SystemInfo` | System name, language, proxy, monitoring configuration |
| `tb_notify` | `Notify` | Message center |
| `tb_notify_conf` | `NotifyConf` | Notification configuration |
| `tb_audit_log` | `AuditLog` | Operation audit |
| `tb_system_logs` | `SystemLogs` | Records used for system log queries |
| `tb_scan_plugin` | `ScanPlugin` | Active scan plugins |
| `tb_scan_template` | `ScanTemplate` | Active scan templates |
| `tb_scan_conf` | `ScanConf` | Periodic scan schedules |
| `tb_scan_tasks` | `ScanTasks` | Scan parent tasks |
| `tb_scan_subtasks` | `ScanSubTasks` | Scan subtasks and plugin results |
| `tb_alert_rule` | `AlertRule` | Flow/correlation alert rules |
| `tb_activity_rule` | `AlertActivityRule` | Sigma/activity rules |
| `tb_alert_activity` | `AlertActivityESDB` | Single-event activity |
| `tb_alert_event` | `AlertEventESDB` | Multi-event threat event |
| `tb_alert_whitelist` | `AlertWhitelist` | Alert whitelist |
| `tb_alert_block` | `AlertBlock` | Threat blocking |
| `tb_sensitive_entry` | `SensitiveEntry` | Sensitive users/groups/computers/honeypot accounts |
| `tb_asset_user` | `AssetUser` | AD user assets |
| `tb_asset_group` | `AssetGroup` | AD group assets |
| `tb_asset_computer` | `AssetComputer` | AD computer assets |
| `tb_export_task` | `ExportTask` | Report export tasks |

## Redis Key Conventions

### Sensor

| Key | Type | Description |
| --- | --- | --- |
| `ada:sensor:cmd_channel` | pubsub | Command delivery |
| `ada:sensor:cmd_task_<task_id>` | hash | Command result |
| `ada:sensor:state` | list | Sensor status events |
| `ada:sensor:id:<uuid>` | hash | Sensor configuration and status |
| `ada:sensor:latest_version` | string | Latest sensor version |
| `ada:sensor:latest_binsum` | string | Latest sensor binary hash |
| `ada:sensor:latest_binfile` | bytes | Latest sensor binary |
| `ada:sensor:collect_stats` | hash | Collection heartbeat, including latest winlog/pktlog times |

### Logs and Detection

| Key | Type | Description |
| --- | --- | --- |
| `ada:evelog_queue` | list | eventlog queue, written by task_server and read by engine |
| `ada:pktlog_queue` | list | pktlog queue, written by task_server/Zeek and read by engine |
| `ada:pktlog_channel` | pubsub | Zeek RedisWriter publishes pktlog; task_server subscribes for ES writes and statistics |
| `ada:engine:reload` | pubsub | engine rule hot reload |
| `ada:engine:flow_rule_map` | hash | Sigma rule id to Flow rule id mapping |
| `ada:engine:flow_field_map` | hash | Flow rule id to field set |
| `ada:engine:instance:<flow_id>_<unique_id>` | zset | Flow instance activity time series |
| `ada:engine:active:<flow_id>` | set | Active Flow instance key set |
| `ada:engine:activity_cache:<mongo_id>` | hash | Activity correlation cache |
| `ada:engine:flow_whitelist...` | hash | Flow whitelist conditions |
| `ada:engine:ldap_search_channel` | pubsub | Async `$v.ldap` cache-miss lookup requests |
| `ada:engine:ldap_search_pending:<hash>` | string | 60s deduplication key for repeated `$v.ldap` misses |
| `ada:server:notify_queue` | list | Notifications pushed by engine/scanner and consumed by task_worker |

### Domain and Asset Cache

| Key | Type | Description |
| --- | --- | --- |
| `ada:server:domain_list` | string/set depending on implementation | Domain list cache |
| `ada:server:ldap:<domain>` | string | LDAP account cache |
| `ada:server:<domain>:ip_relate_dc` | hash | IP to DC FQDN mapping |
| `ada:engine:dc_ip:<ip>` | string | Hostname lookup by IP for Zeek RedisWriter |
| `ada:engine:<domain>:sensitive_users` | set | Sensitive users; can be filled by scheduled LDAP sync or async `$v.ldap` miss handling |
| `ada:engine:<domain>:sensitive_groups` | set | Sensitive groups; can be filled by scheduled LDAP sync or async `$v.ldap` miss handling |
| `ada:engine:<domain>:sensitive_computers` | set | Sensitive computers; can be filled by scheduled LDAP sync or async `$v.ldap` miss handling |
| `ada:engine:<domain>:honeypot_accounts` | set | Honeypot accounts |

### System and Dashboard

| Key | Type | Description |
| --- | --- | --- |
| `ada:server:stats:info` | hash | ES and system status information |
| `ada:server:stats:load` | list | System load monitoring |
| `ada:server:stats:cpu` | list | CPU monitoring |
| `ada:server:stats:mem` | list | Memory monitoring |
| `ada:server:stats:net_rx` | list | Network receive |
| `ada:server:stats:net_tx` | list | Network transmit |
| `ada:server:stats:cfg` | hash | Monitoring threshold configuration |
| `ada:server:stats:winlog:<domain>` | zset | Per-minute winlog statistics |
| `ada:server:stats:pktlog:<domain>` | zset | Per-minute pktlog statistics |

## Elasticsearch Indices

| Index | Writer | Purpose |
| --- | --- | --- |
| `ada-eventlog-YYYY.MM.DD` | task_server | Raw Windows eventlog search |
| `ada-packetlog-YYYY.MM.DD` | task_server | Raw pktlog search |
| `ada-activity` | engine | Activity search and alert behavior display |

Field conventions:

- Time fields use `@timestamp`.
- packetlog `ProtocolFields` is an object field with indexing disabled to avoid dynamic field explosion.
- engine activity JSON is shared by MongoDB and ES models. When changing fields, update both `backend/model/tables.go` and `engine/model/types.go`.

## Data Consistency Notes

- MongoDB is the source of truth for business state; ES is mainly for search and display, so do not judge business task failure by ES alone.
- Redis queues are async boundaries. Backlog does not mean data loss, but long-lived backlog indicates an abnormal consumer.
- Flow correlation depends on Redis cache TTL. After the window expires, historical activity can no longer be correlated.
- `$v.ldap` uses Redis as the synchronous hot-path cache. LDAP misses are published to tasker and deduplicated with `ada:engine:ldap_search_pending:<hash>` for 60 seconds.
- Zeek RedisWriter depends on `ada:engine:dc_ip:<ip>` to map IP addresses to hostnames. Missing mappings affect domain attribution.
