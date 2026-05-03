# Development, Testing, and Troubleshooting Entrypoints

This document records common development, build, self-test, and troubleshooting entrypoints for this repository. It covers only the `ada` repository; the frontend repository is the sibling `../ada-web`.

## Common Build Commands

The root `Makefile` provides the main Go binary build targets:

```bash
make apiserver
make task_server
make task_worker
make engine
make scanner
make all
```

Build outputs are written to `bin/` by default:

- `bin/apiserver`
- `bin/task_server`
- `bin/task_worker`
- `bin/engine`
- `bin/scanner`

`make apiserver` first runs `gen_proto`, which requires local `protoc` and the corresponding Go plugin.

## Docker Build

Use `build.sh` under `script/docker`:

```bash
./build.sh build backend
./build.sh build engine
./build.sh build scanner
./build.sh build zeek
./build.sh build all
```

Release flow:

```bash
./build.sh package backend
./build.sh deploy backend
./build.sh release backend
```

Notes:

- `build_backend` first builds sibling `../ada-web`, then copies frontend `dist` into the backend image build context.
- `build_engine` copies `engine/rules` into the engine image build context.
- `build_scanner` depends on the scanner package and Python plugin runtime being prepared correctly.

## Unit Test Entrypoints

Quick tests listed in README:

```bash
go test ./infra/loghook
go test ./backend/tasker/worker -run '^$'
```

Common focused tests:

```bash
go test ./backend/tasker/server
go test ./backend/tasker/worker
go test ./engine/sigma
go test ./agent/sensor/plugin
```

When testing backend/engine locally on macOS, set an isolated Go build cache to avoid permission issues or cache pollution:

```bash
GOCACHE=/tmp/ada-go-build go test ./...
```

Full `go test ./...` can be affected by platform constraints, Windows build tags, external services, embedded scanner packages, or local dependencies. For small changes, prefer focused tests for the affected package.

## Log Locations

Common logs inside containers:

| Module | Path |
| --- | --- |
| supervisor | `/home/adadmin/logs/supervisord.log` |
| apiserver | `/home/adadmin/logs/apiserver.log` and `apiserver_stderr.log` |
| task_server | `/home/adadmin/logs/tasker_server.log` or stderr file |
| task_worker | `/home/adadmin/logs/tasker_worker.log` or stderr file |
| engine | `/home/adadmin/logs/engine.log` |
| scanner | `/home/adadmin/logs/scanner.log` |
| nginx access | `/var/log/nginx/ada_access.log` |
| nginx error | `/var/log/nginx/ada_error.log` |
| Windows sensor | `C:\Program Files\adaegis\logs\sensor.log` |

Actual file names depend on `ProjectName` and the tasker moduleName. During troubleshooting, use `LogPath` in configuration and startup logs as the source of truth.

## Common Troubleshooting Paths

### Frontend/API Unreachable

1. Check whether nginx is running.
2. Check whether `/home/adadmin/static` contains the latest frontend assets.
3. Check whether nginx forwards `/ada.ADA/` to `127.0.0.1:8800`.
4. Check whether apiserver is listening for gRPC.
5. Check whether the token is expired or missing permissions.

### MCP 401

1. Requests must include `authorization: Bearer <token>`.
2. The token can be a user JWT or an AccessKey secret hash.
3. MCP tool calls reuse gRPC ACL; successful authentication does not imply authorization.

### Dashboard winlog/pktlog Statistics Stay at 0

1. Check whether task_server receives syslog or `ada:pktlog_channel`.
2. Check whether hostname can be resolved to a domain.
3. Check whether Redis `ada:server:stats:winlog:<domain>` or `ada:server:stats:pktlog:<domain>` contains recent minute data.
4. ES is only used for search; statistics come from Redis.

### Raw Logs Exist but No Alerts

1. Check whether `ada:evelog_queue` or `ada:pktlog_queue` has backlog.
2. Check whether engine is running and rules are loaded.
3. Check whether the Sigma rule `logsource`, `detection`, `fields`, and `unique_fields` match actual fields.
4. Check whether `tb_alert_activity` has activity records.
5. If activity exists but event does not, check Flow rules, Redis flow instances, and `match_by` parsing.
6. If `$v.ldap` is involved, check the Redis lookup set, `ada:engine:ldap_search_pending:<hash>`, and tasker logs for `ada:engine:ldap_search_channel`.

### Scan Tasks Do Not Move

1. Check whether apiserver successfully calls task_server.
2. Check whether `ada:tasker:task_queue` has Machinery task backlog.
3. Check whether task_worker creates `tb_scan_tasks` and `tb_scan_subtasks`.
4. Check whether scanner starts the scgo worker.
5. Check whether the Celery-compatible task name is `tasks.<type>.execute_<type>`.
6. Check Python plugin runtime version and `.so` compatibility.

### Sensor Startup Failure

1. On the target host, enter `C:\Program Files\adaegis` and run the exe manually to capture stderr.
2. Confirm whether `sensor.cfg` uses the current AES-GCM format.
3. Confirm Redis TLS, ACL user, server address, and ports.
4. Confirm Npcap, tshark runtime, and NIC configuration.
5. Avoid long-running self-upgrade work during startup to prevent Windows SCM 1053/7009.

## Change Notes

- After changing protobuf, regenerate code and confirm whether the frontend gRPC-web client also needs syncing.
- When changing rule structure, also check YAML, MongoDB models, apiserver output, and engine loading logic.
- When changing activity/event models, update both `backend/model/tables.go` and `engine/model/types.go`.
- When changing Redis key or queue names, also check tasker, engine, sensor, Zeek plugins, and dashboard readers.
- When changing sensor packet/tshark fields, update ES mapping, engine rule fields, and tests together.
- When changing scanner plugin context, check baseline, leak, and weakpwd task types together.
