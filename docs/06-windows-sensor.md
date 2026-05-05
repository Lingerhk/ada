# Windows Sensor Technical Notes

Windows Sensor is a service deployed on domain controllers or target Windows hosts. Its service name is `adaegis`. It handles registration, status reporting, plugin control, event log collection, network traffic collection, and self-upgrade.

## Entrypoint and Run Modes

Entrypoint file:

- `agent/sensor/cmd/sensor.go`
- Windows build tag: `//go:build windows`

Command modes:

| Argument | Behavior |
| --- | --- |
| `-m <manager_ip>` | Update the server address in configuration and exit |
| `-l` | List NIC information and exit |
| `-r` | Register with the server by using the registration code in configuration and exit |
| No argument | Run as a Windows service |

After the service starts, it launches:

- upgrade: listens for and fetches self-upgrades.
- plugin event: continuously consumes server commands.
- plugin serve: starts, stops, or reloads collection plugins according to Redis configuration.
- auto resource limit: automatically adjusts plugin runtime when resource limits are exceeded.
- stats: periodically reports sensor, plugin, and host status.

## Configuration

Configuration loading logic is in `agent/sensor/config/config.go`.

Two file formats are supported:

- `sensor.yaml`: plaintext YAML.
- `sensor.cfg`: AES-GCM encrypted and base64-encoded configuration.

Configuration items include:

| Configuration | Description |
| --- | --- |
| `Redis.Username` | ACL user used by the sensor for Redis TLS connections, default `ada_sensor` |
| `Redis.Password` | Redis ACL password |
| `Redis.Port` | Redis TLS port, default `9091` |
| `Sensor.RegHost` | Server address |
| `Sensor.EvtSrvPort` | eventlog/tshark syslog port, default `9092` |
| `Sensor.PktSrvPort` | raw packet forwarding port, default `9093` |
| `Sensor.RegCode` | Registration code |

The sensor embeds client certificate, client key, and CA certificate for Redis TLS connections.

## Redis Control Plane

Key keys and channels:

| Key / Channel | Type | Description |
| --- | --- | --- |
| `ada:sensor:cmd_channel` | pubsub | Server command delivery |
| `ada:sensor:cmd_task_<task_id>` | hash | Command execution result |
| `ada:sensor:state` | list | Sensor registration and status events |
| `ada:sensor:id:<uuid>` | hash | Configuration and status for one sensor |
| `ada:sensor:latest_version` | string | Latest version number |
| `ada:sensor:latest_binsum` | string | Latest binary sha256 |
| `ada:sensor:latest_binfile` | bytes | Latest binary content |

The sensor uses `PSUBSCRIBE` to consume commands because the production ACL user allows `psubscribe` but may not allow normal `subscribe`.

## Plugin Model

Plugin entrypoints are under `agent/sensor/plugin`.

| Plugin | Code | Responsibility |
| --- | --- | --- |
| eventlog plugin | `plugin_evt.go` | Reads Windows event logs and sends them to task_server through syslog |
| packet plugin | `plugin_pkt.go` | Captures raw packets with pcap and sends them to Zeek over UDP |
| tshark plugin | `plugin_tshark.go` | Starts tshark, generates normalized pktlog JSON, and sends it to task_server through syslog |
| block plugin | `plugin_block.go` | Related to blocking policies |
| rpcfw/ldapfw | Controlled through standalone service names | Related to RPC/LDAP protection plugins |

Plugin configuration is read from the `ada:sensor:id:<uuid>` hash. Common fields include:

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

Processing flow:

1. Build a Windows Event Log input.
2. Build a syslog output with tag `ADASensor`.
3. Use the local FQDN as hostname.
4. Read configured channels such as Security.
5. Send events over UDP to `<RegHost>:<EvtSrvPort>`.

task_server depends on the syslog hostname to extract the domain, so the hostname format must allow domain inference.

## packet plugin

Processing flow:

1. Use `pcap.FindAllDevs` to find configured NICs.
2. Run `pcap.OpenLive` for each NIC.
3. Set the BPF filter.
4. Send packet data over UDP to `<RegHost>:<PktSrvPort>`.
5. The Zeek container receives it on `9093/udp`.

Notes:

- `snapshotLen` is 1500.
- The default BPF excludes traffic to the ADAegis server to avoid collecting control-plane communication.
- Npcap is a Windows packet capture prerequisite and is included in the sensor package.

## tshark plugin

The tshark plugin is useful when protocol fields should be extracted directly on Windows.

Processing flow:

1. Select the tshark path from configuration.
2. Start tshark subprocesses by NIC.
3. Parse EK JSON or field rows.
4. Normalize the output into pktlog events.
5. Write `@timestamp`, and remove `FrameTimeEpoch` and `FrameProtocols`.
6. Send the events to task_server through syslog.

Typical output fields:

- `LogType=pktlog`
- `Source=tshark`
- `EventType`
- `Hostname`
- `SensorTime`
- `@timestamp`
- `SrcIp`, `DstIp`, `SrcPort`, `DstPort`
- `Protocol`
- `ProtocolFields`

## Self-Upgrade

Self-upgrade logic is in `agent/sensor/upgrade`. Version information and binaries are delivered through Redis keys.

Key behavior:

- The first upgrade check is delayed after service startup to avoid Windows SCM startup timeout.
- After binary replacement, the current process must exit so the Windows service manager can start the new process.
- To verify that self-upgrade is fetched by the sensor itself, inspect Redis `GET ada:sensor:latest_*`.

## Packaging

Sensor packages are generated by tools such as `agent/sensor/tools/pkg_sensor` together with install scripts under `agent/script`. A package usually contains:

- `adaegis.exe`
- `sensor.cfg` or `sensor.yaml`
- `install-adaegis.ps1`
- `uninstall-adaegis.ps1`
- `npcap-0.93.exe`
- `tshark/` runtime
- Other plugin packages

When changing the sensor package, distinguish test environment configuration from default configuration, and avoid packaging test server addresses into production packages.
