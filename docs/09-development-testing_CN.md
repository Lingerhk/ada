# 开发、测试与排障入口

本文档记录本仓库日常开发、构建、自测和排障入口。它只覆盖 `ada` 仓库；前端仓库在同级 `../ada-web`。

## 常用构建命令

根目录 `Makefile` 提供主要 Go 二进制构建目标：

```bash
make apiserver
make task_server
make task_worker
make engine
make scanner
make all
```

生成物默认输出到 `bin/`：

- `bin/apiserver`
- `bin/task_server`
- `bin/task_worker`
- `bin/engine`
- `bin/scanner`

`make apiserver` 会先执行 `gen_proto`，依赖本机存在 `protoc` 和对应 Go plugin。

## Docker 构建

在 `script/docker` 下使用 `build.sh`：

```bash
./build.sh build backend
./build.sh build engine
./build.sh build scanner
./build.sh build zeek
./build.sh build all
```

发布流程：

```bash
./build.sh package backend
./build.sh deploy backend
./build.sh release backend
```

注意：

- `build_backend` 会先构建同级 `../ada-web`，再把前端 dist 复制进 backend 镜像构建目录。
- `build_engine` 会复制 `engine/rules` 到 engine 镜像构建目录。
- `build_scanner` 依赖 scanner 包和 Python 插件运行时是否已正确准备。

## 单元测试入口

README 中列出的快速测试：

```bash
go test ./infra/loghook
go test ./backend/tasker/worker -run '^$'
```

常见局部测试：

```bash
go test ./backend/tasker/server
go test ./backend/tasker/worker
go test ./engine/sigma
go test ./agent/sensor/plugin
```

如果在本地 macOS 上测试 backend/engine，建议设置独立 Go build cache，避免权限或缓存污染：

```bash
GOCACHE=/tmp/ada-go-build go test ./...
```

全量 `go test ./...` 可能受平台、Windows build tag、外部服务、内嵌扫描包或本机依赖影响。修改范围小时，优先跑对应包的 focused tests。

## 日志位置

容器内常见日志：

| 模块 | 路径 |
| --- | --- |
| supervisor | `/home/adadmin/logs/supervisord.log` |
| apiserver | `/home/adadmin/logs/apiserver.log` 和 `apiserver_stderr.log` |
| task_server | `/home/adadmin/logs/tasker_server.log` 或 stderr 文件 |
| task_worker | `/home/adadmin/logs/tasker_worker.log` 或 stderr 文件 |
| engine | `/home/adadmin/logs/engine.log` |
| scanner | `/home/adadmin/logs/scanner.log` |
| nginx access | `/var/log/nginx/ada_access.log` |
| nginx error | `/var/log/nginx/ada_error.log` |
| Windows sensor | `C:\Program Files\adaegis\logs\sensor.log` |

实际文件名受 `ProjectName` 和 tasker moduleName 影响，排障时以配置中的 `LogPath` 和启动日志为准。

## 常见排障路径

### 前端/API 不通

1. 查 nginx 是否运行。
2. 查 `/home/adadmin/static` 是否存在最新前端资源。
3. 查 nginx `/ada.ADA/` 是否转发到 `127.0.0.1:8800`。
4. 查 apiserver 是否监听 gRPC。
5. 查 token 是否过期或缺少权限。

### MCP 401

1. 请求必须携带 `authorization: Bearer <token>`。
2. token 可以是用户 JWT，也可以是 AccessKey secret hash。
3. MCP 工具调用复用 gRPC ACL，认证成功不代表有权限。

### Dashboard winlog/pktlog 统计为 0

1. 查 task_server 是否收到 syslog 或 `ada:pktlog_channel`。
2. 查 hostname 是否能解析出 domain。
3. 查 Redis `ada:server:stats:winlog:<domain>` 或 `ada:server:stats:pktlog:<domain>` 是否有最近分钟数据。
4. 查 ES 只用于检索，统计值来自 Redis。

### 有原始日志但没有告警

1. 查 `ada:evelog_queue` 或 `ada:pktlog_queue` 是否积压。
2. 查 engine 是否启动并加载规则。
3. 查 license runtime check 是否让 engine 进入 pending。
4. 查 Sigma rule 的 `logsource`、`detection`、`fields`、`unique_fields` 是否匹配实际字段。
5. 查 `tb_alert_activity` 是否有 activity。
6. 如果 activity 有但 event 没有，查 Flow 规则和 Redis flow instance。

### 扫描任务不动

1. 查 apiserver 是否成功调用 task_server。
2. 查 `ada:tasker:task_queue` 是否有 Machinery 任务积压。
3. 查 task_worker 是否创建 `tb_scan_tasks` 和 `tb_scan_subtasks`。
4. 查 scanner 是否启动 scgo worker。
5. 查 Celery 兼容 task name 是否为 `tasks.<type>.execute_<type>`。
6. 查 Python 插件运行时版本和 `.so` 兼容性。

### Sensor 启动失败

1. 在目标机直接进入 `C:\Program Files\adaegis` 手工运行 exe，捕获 stderr。
2. 确认 `sensor.cfg` 是否是当前 AES-GCM 格式。
3. 确认 Redis TLS、ACL 用户、服务端地址和端口。
4. 确认 Npcap、tshark runtime 和网卡配置。
5. 启动阶段不要做耗时自升级，避免 Windows SCM 1053/7009。

## 变更注意事项

- 修改 protobuf 后需要重新生成并确认前端 gRPC-web 客户端是否同步。
- 修改规则结构时，同时关注 YAML、MongoDB 模型、apiserver 输出和 engine 加载逻辑。
- 修改 activity/event 模型时，同步 `backend/model/tables.go` 与 `engine/model/types.go`。
- 修改 Redis key 或 queue 名称时，同时检查 tasker、engine、sensor、Zeek plugin 和 dashboard 读取方。
- 修改 sensor packet/tshark 字段时，同时更新 ES mapping、engine 规则字段和测试。
- 修改 scanner 插件上下文时，同时检查 baseline、leak、weakpwd 三类任务。
