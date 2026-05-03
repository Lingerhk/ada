# Windows Sensor 技术说明

Windows Sensor 是部署在域控或目标 Windows 主机上的服务，服务名为 `adaegis`。它负责注册、状态上报、插件控制、事件日志采集、网络流量采集和自升级。

## 入口和运行模式

入口文件：

- `agent/sensor/cmd/sensor.go`
- Windows build tag：`//go:build windows`

命令模式：

| 参数 | 行为 |
| --- | --- |
| `-m <manager_ip>` | 修改配置中的服务端地址并退出 |
| `-l` | 列出网卡信息并退出 |
| `-r` | 使用配置中的注册码向服务端注册并退出 |
| 无参数 | 以 Windows 服务方式运行 |

服务运行后会启动：

- upgrade：监听和拉取自升级。
- plugin event：持续消费服务端命令。
- plugin serve：按 Redis 配置启动/停止/重载采集插件。
- auto resource limit：资源超限时自动调整插件运行。
- stats：定期上报 sensor、插件和主机状态。

## 配置

配置加载逻辑位于 `agent/sensor/config/config.go`。

支持两种文件：

- `sensor.yaml`：明文 YAML。
- `sensor.cfg`：AES-GCM 加密并 base64 编码的配置。

配置项包括：

| 配置 | 说明 |
| --- | --- |
| `Redis.Username` | sensor 连接 Redis TLS 使用的 ACL 用户，默认 `ada_sensor` |
| `Redis.Password` | Redis ACL 密码 |
| `Redis.Port` | Redis TLS 端口，默认 `9091` |
| `Sensor.RegHost` | 服务端地址 |
| `Sensor.EvtSrvPort` | eventlog/tshark syslog 端口，默认 `9092` |
| `Sensor.PktSrvPort` | raw packet 转发端口，默认 `9093` |
| `Sensor.RegCode` | 注册码 |

sensor 内嵌 client certificate、client key 和 CA，用于连接 Redis TLS。

## Redis 控制面

关键 key 和 channel：

| Key / Channel | 类型 | 说明 |
| --- | --- | --- |
| `ada:sensor:cmd_channel` | pubsub | 服务端下发命令 |
| `ada:sensor:cmd_task_<task_id>` | hash | 命令执行结果 |
| `ada:sensor:state` | list | sensor 注册和状态上报事件 |
| `ada:sensor:id:<uuid>` | hash | 单个 sensor 的配置和状态 |
| `ada:sensor:latest_version` | string | 最新版本号 |
| `ada:sensor:latest_binsum` | string | 最新二进制 sha256 |
| `ada:sensor:latest_binfile` | bytes | 最新二进制内容 |

sensor 使用 `PSUBSCRIBE` 消费命令，因为生产 ACL 用户允许 `psubscribe` 而不一定允许普通 `subscribe`。

## 插件模型

插件入口在 `agent/sensor/plugin`。

| 插件 | 代码 | 职责 |
| --- | --- | --- |
| eventlog plugin | `plugin_evt.go` | 读取 Windows 事件日志，通过 syslog 发给 task_server |
| packet plugin | `plugin_pkt.go` | 用 pcap 抓原始包，通过 UDP 发给 Zeek |
| tshark plugin | `plugin_tshark.go` | 启动 tshark，生成归一化 pktlog JSON，通过 syslog 发给 task_server |
| block plugin | `plugin_block.go` | 与阻断策略相关 |
| rpcfw/ldapfw | 通过独立服务名控制 | 与 RPC/LDAP 防护插件相关 |

插件配置从 `ada:sensor:id:<uuid>` hash 读取。常见字段包括：

- `pkt_plugin_switch`
- `log_plugin_switch`
- `tshark_plugin_switch`
- `bind_net_iface`
- `pkt_bpf_filter`
- `log_evt_filter`
- `tshark_path`
- `tshark_capture_filter`
- `tshark_display_filter`
- `tshark_fields`
- `limit_cpu_max`
- `limit_mem_max`

## eventlog plugin

处理过程：

1. 构造 Windows Event Log input。
2. 构造 syslog output，tag 为 `ADASensor`。
3. hostname 使用本机 FQDN。
4. 按配置读取 channel，例如 Security 等。
5. 通过 UDP 发到 `<RegHost>:<EvtSrvPort>`。

task_server 依赖 syslog hostname 提取 domain，因此主机名格式必须能反推出域。

## packet plugin

处理过程：

1. 用 `pcap.FindAllDevs` 找到配置网卡。
2. 对每个网卡 `pcap.OpenLive`。
3. 设置 BPF 过滤器。
4. 把 packet data 通过 UDP 发到 `<RegHost>:<PktSrvPort>`。
5. Zeek 容器在 `9093/udp` 接收。

注意点：

- `snapshotLen` 为 1500。
- BPF 默认会排除到 ADAegis 服务端的流量，避免采集控制面通信。
- Npcap 是 Windows 抓包前置依赖，安装包由 sensor package 携带。

## tshark plugin

tshark plugin 适合在 Windows 端直接提取协议字段。

处理过程：

1. 根据配置选择 tshark 路径。
2. 按网卡启动 tshark 子进程。
3. 解析 EK JSON 或字段行。
4. 归一化为 pktlog 事件。
5. 写入 `@timestamp`，删除 `FrameTimeEpoch` 和 `FrameProtocols`。
6. 通过 syslog 发给 task_server。

典型输出字段：

- `LogType=pktlog`
- `Source=tshark`
- `EventType`
- `Hostname`
- `SensorTime`
- `@timestamp`
- `SrcIp`、`DstIp`、`SrcPort`、`DstPort`
- `Protocol`
- `ProtocolFields`

## 自升级

自升级逻辑位于 `agent/sensor/upgrade`，版本信息和二进制通过 Redis key 下发。

关键行为：

- 服务启动后延迟执行首次升级检查，避免 Windows SCM 判定服务启动超时。
- 二进制替换后需要退出当前进程，由 Windows 服务管理器重新拉起新进程。
- 验证自升级是否由 sensor 自己拉取，可观察 Redis `GET ada:sensor:latest_*`。

## 打包

sensor 包由 `agent/sensor/tools/pkg_sensor` 等工具和 `agent/script` 下的安装脚本配合生成。包内通常包含：

- `adaegis.exe`
- `sensor.cfg` 或 `sensor.yaml`
- `install-adaegis.ps1`
- `uninstall-adaegis.ps1`
- `npcap-0.93.exe`
- `tshark/` runtime
- 其他插件包

变更 sensor 包时要区分测试环境配置和默认配置，避免把测试服务端地址打进正式包。
