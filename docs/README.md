# ADAegis 技术文档导航

本文档集面向第一次接触 `ada` 仓库的研发、运维和安全工程师。`ada` 是 ADAegis 的后端、任务调度、检测引擎、主动扫描、传感器和 Zeek 插件仓库；前端源码在同级 `../ada-web`，但最终静态资源会被打进本仓库的 backend 镜像。

编号文档提供中英文版本：英文版使用原始 `01-...md` 文件名，中文版使用同名 `_CN.md` 后缀。

## 推荐阅读顺序

1. 系统架构总览：[EN](./01-architecture-overview.md) / [CN](./01-architecture-overview_CN.md)：先理解组件边界、控制面、数据面和核心进程。
2. 运行时与部署拓扑：[EN](./02-runtime-deployment.md) / [CN](./02-runtime-deployment_CN.md)：再看容器、端口、配置、构建和发布路径。
3. 采集与检测数据流：[EN](./03-ingestion-dataflow.md) / [CN](./03-ingestion-dataflow_CN.md)：理解 winlog、pktlog、Zeek、Redis 队列、ES 写入和 dashboard 统计。
4. 后端 API、认证与任务调度：[EN](./04-backend-api-tasker.md) / [CN](./04-backend-api-tasker_CN.md)：理解 apiserver、gRPC、MCP、tasker 和异步任务。
5. 规则引擎与威胁检测：[EN](./05-rule-engine.md) / [CN](./05-rule-engine_CN.md)：理解 Sigma 规则、Flow 关联、告警落库和规则热加载。
6. Windows Sensor 技术说明：[EN](./06-windows-sensor.md) / [CN](./06-windows-sensor_CN.md)：理解传感器注册、插件、采集、命令下发和自升级。
7. 主动扫描系统：[EN](./07-scanner.md) / [CN](./07-scanner_CN.md)：理解 baseline、leak、weakpwd 扫描任务如何被创建、分发和执行。
8. 数据模型与存储约定：[EN](./08-data-model-storage.md) / [CN](./08-data-model-storage_CN.md)：快速查 Redis key、MongoDB collection、ES index 的职责。
9. 开发、测试与排障入口：[EN](./09-development-testing.md) / [CN](./09-development-testing_CN.md)：日常构建、自测、日志、排障和变更注意事项。

## 仓库主入口

| 范围 | 入口文件 | 说明 |
| --- | --- | --- |
| API Server | `backend/apiserver/cmd/apiserver.go` | gRPC API、HTTP 辅助端点、MCP、Kibana/WebSSH 代理 |
| Task Server | `backend/tasker/cmd/server/main.go` | gRPC 任务接口、cron、syslog/pktlog 接收、Redis pubsub 处理 |
| Task Worker | `backend/tasker/cmd/worker/main.go` | Machinery 任务执行器，执行同步、扫描编排、通知、导出 |
| Engine | `engine/cmd/engine.go` | Sigma 单事件匹配和 Flow 多事件关联 |
| Scanner | `scanner/cmd/scanner.go` | 主动扫描 worker，消费 Celery 兼容任务并运行 Python 插件 |
| Sensor | `agent/sensor/cmd/sensor.go` | Windows 服务，负责注册、插件控制、采集、状态上报和自升级 |
| Zeek | `zeek/plugins` | TrafficReceiver 包接收插件和 RedisWriter 日志写入插件 |

## 快速结论

- `ada_backend` 容器不是单一进程，它通过 supervisor 同时运行 `nginx`、`apiserver`、`task_server`、`task_worker`。
- `Redis` 是核心中间层：承载异步任务 broker/backend、sensor 控制状态、日志队列、规则引擎缓存、通知队列和统计数据。
- `MongoDB` 是业务事实库：用户、域、sensor、规则、扫描任务、告警、资产、通知等主要业务对象都在 MongoDB。
- `Elasticsearch` 是日志和检索库：eventlog、packetlog、activity 等用于检索、趋势和 Kibana 展示。
- 检测链路分两层：Sigma 先把单条 winlog/pktlog 转成 activity，Flow 再在 Redis 中按时间窗口关联 activity 成 threat event。
- 主动扫描不是 apiserver 本地执行：调用链是 `apiserver -> task_server -> task_worker -> scanner(scgo) -> Python 插件`。

## 文档维护规则

- 修改架构、端口、队列、collection、index 或任务链路时，同步更新对应文档。
- 文档示例中不要写入生产口令、license、token 或真实客户域信息。
- 涉及 live 环境的结论要重新验证，不要只复用旧排障记录。
