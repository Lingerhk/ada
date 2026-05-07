# ADAegis

[English](README.md)

ADAegis 是一个面向 Active Directory 与企业身份环境的安全平台。它帮助安全团队发现身份风险、采集 Windows 与网络安全遥测、检测可疑行为，并在统一 Portal 中完成告警调查和处置。

ADAegis 适用于需要持续观察域控、用户活动、认证行为、网络协议痕迹、弱口令、风险配置和身份攻击路径的团队。

> 介绍视频：待补充。后续可将本行替换为视频链接。

## ADAegis 解决什么问题

- Active Directory 环境很难只靠终端或网络工具完整观察。
- 需要对 AD 进行安全审计，持续发现风险并指导加固。
- 身份攻击通常横跨 Windows 事件、认证流量、网络协议和账号行为。
- 安全团队需要可复用的方式评估域风险、验证安全状态并调查告警。
- 规则开发应该基于真实可采集的遥测，而不是脱离 Sensor 能力。

ADAegis 将采集、检测、风险评估、告警处置和运维流程整合到一个可部署的安全栈中。

## 核心亮点

- **聚焦 Active Directory 安全**：围绕域资产、用户、Sensor、Windows 事件、认证行为和 AD 风险检查构建。
- **整合多源遥测**：统一处理 Windows 事件日志、网络协议日志和 Sensor 状态。
- **威胁检测**：支持 Sigma 风格单事件检测，也支持多事件关联检测身份攻击行为。
- **MCP 协议与 AI Agent（Coming soon）**：通过 MCP 协议开放安全工作流，后续将支持 AI Agent 辅助威胁检测、告警调查和安全运营。
- **风险评估**：覆盖基线检查、泄露检查、弱口令检查和扫描任务跟踪。
- **Portal 优先的工作流**：提供 Dashboard、域管理、Sensor 管理、扫描结果、规则、告警和报告等操作入口。
- **Docker 化部署**：提供 compose 文件和镜像构建脚本，便于重复部署。
- **便于开发扩展**：后端、引擎、扫描器、Sensor、部署脚本和技术文档集中在同一个 Go 仓库中。

## 仓库

- 后端与核心服务：[github.com/Lingerhk/ada](https://github.com/Lingerhk/ada)
- 前端 Portal：[github.com/Lingerhk/ada-web](https://github.com/Lingerhk/ada-web)

从源码构建完整 backend 镜像时，前端仓库需要与本仓库放在同级目录。

## 快速部署

标准 Docker 部署资源位于 `script/docker`。

### 前置条件

- Docker Engine
- Docker Compose
- Linux 主机，并为 Elasticsearch 和后端服务预留足够内存
- 已经准备好的 ADAegis 镜像，或能够本地构建镜像的环境

### 使用已有镜像启动

如果目标主机已经具备所需镜像：

```bash
cd script/docker
docker compose up -d
docker compose ps
```

Portal 默认由 backend 服务通过 `80` 端口提供。

### 从源码构建镜像

保持后端与前端仓库为同级目录：

```text
adaegis/
  ada/
  ada-web/
```

然后构建并启动：

```bash
cd ada/script/docker
./build.sh build all
docker compose up -d
docker compose ps
```

如果你的 checkout 路径与构建脚本默认 workspace 布局不同，请先调整 `script/docker/build.sh` 顶部的路径变量。

## 本地开发

### 后端

```bash
cd ada
go mod download
go test ./engine/sigma
go test ./engine/flow
```

需要时构建主要后端二进制：

```bash
make apiserver
make task_server
make task_worker
make engine
make scanner
```

`make apiserver` 会重新生成 protobuf 输出，运行该目标前请确认已经安装 `protoc` 和 Go protobuf 插件。

### 前端

将前端仓库 clone 到 `ada` 同级目录：

```bash
git clone git@github.com:Lingerhk/ada-web.git
```

前端依赖安装、开发服务和构建命令请参考前端仓库文档：

- [github.com/Lingerhk/ada-web](https://github.com/Lingerhk/ada-web)

### 文档

深入技术细节可以先看文档索引，再按主题阅读：

- [技术文档索引](docs/README.md)
- [系统架构总览](docs/01-architecture-overview_CN.md)
- [运行时与部署拓扑](docs/02-runtime-deployment_CN.md)
- [采集与检测数据流](docs/03-ingestion-dataflow_CN.md)
- [后端 API、认证与任务调度](docs/04-backend-api-tasker_CN.md)
- [规则引擎与威胁检测](docs/05-rule-engine_CN.md)
- [Windows Sensor](docs/06-windows-sensor_CN.md)
- [主动扫描系统](docs/07-scanner_CN.md)
- [数据模型与存储约定](docs/08-data-model-storage_CN.md)
- [开发、测试与排障入口](docs/09-development-testing_CN.md)
- [Sensor debug memo](docs/sensor-debug-memo.md)

## 反馈问题

Bug、功能建议和文档问题请通过 GitHub issues 反馈：

- [github.com/Lingerhk/ada/issues](https://github.com/Lingerhk/ada/issues)

反馈问题时建议提供：

- ADAegis 版本或 commit
- 部署方式
- 复现步骤
- 期望行为
- 相关日志或截图，注意移除敏感信息

社区联系方式：

- Telegram 群：[ADAegis Official Support](https://t.me/+6zDk06KqdpBiNjc1)

## License

ADAegis 使用 [MIT License](https://opensource.org/license/mit) 发布。

## 项目状态

ADAegis 正在持续开发中。接口、部署脚本和文档会随着项目演进而调整。
