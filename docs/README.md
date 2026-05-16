# ADAegis Technical Documentation

[中文版本](./README_CN.md)

This documentation set is for engineers, operators, and security practitioners who are new to the `ada` repository. `ada` contains the ADAegis backend, task scheduling, detection engine, active scanner, Windows Sensor, and Zeek plugin code. The frontend source lives in the sibling `../ada-web` repository, while its built static assets are packaged into the backend image.

Numbered documents are available in both English and Chinese. English documents use the original `01-...md` file names, and Chinese documents use the matching `_CN.md` suffix.

## Recommended Reading Order

1. System architecture overview: [EN](./01-architecture-overview.md) / [CN](./01-architecture-overview_CN.md): start with component boundaries, control plane, data plane, and core processes.
2. Runtime and deployment topology: [EN](./02-runtime-deployment.md) / [CN](./02-runtime-deployment_CN.md): then review containers, ports, configuration, build flow, and release flow.
3. Collection and detection data flow: [EN](./03-ingestion-dataflow.md) / [CN](./03-ingestion-dataflow_CN.md): understand winlog, pktlog, Zeek, Redis queues, Elasticsearch writes, and dashboard statistics.
4. Backend API, authentication, and task scheduling: [EN](./04-backend-api-tasker.md) / [CN](./04-backend-api-tasker_CN.md): understand apiserver, gRPC, MCP, tasker, and asynchronous tasks.
5. Rule engine and threat detection: [EN](./05-rule-engine.md) / [CN](./05-rule-engine_CN.md): understand Sigma rules, Flow correlation, alert persistence, and rule hot reload.
6. Windows Sensor technical notes: [EN](./06-windows-sensor.md) / [CN](./06-windows-sensor_CN.md): understand sensor registration, plugins, collection, command dispatch, and self-upgrade.
7. Active scanner: [EN](./07-scanner.md) / [CN](./07-scanner_CN.md): understand how baseline, leak, and weak-password scan tasks are created, distributed, and executed.
8. Data model and storage conventions: [EN](./08-data-model-storage.md) / [CN](./08-data-model-storage_CN.md): quickly locate Redis keys, MongoDB collections, and Elasticsearch index responsibilities.
9. Development, testing, and troubleshooting: [EN](./09-development-testing.md) / [CN](./09-development-testing_CN.md): daily build commands, focused tests, logs, troubleshooting, and change notes.
10. GOAD integration and validation: [EN](./10-goad-integration.md) / [CN](./10-goad-integration_CN.md): deploy GOAD on Proxmox, prepare DC audit policy, install sensors, and validate alerts.

## Main Repository Entrypoints

| Area | Entrypoint | Description |
| --- | --- | --- |
| API Server | `backend/apiserver/cmd/apiserver.go` | gRPC API, HTTP helper endpoints, MCP, Kibana/WebSSH proxy |
| Task Server | `backend/tasker/cmd/server/main.go` | gRPC task interface, cron, syslog/pktlog receiving, Redis pubsub handling |
| Task Worker | `backend/tasker/cmd/worker/main.go` | Machinery task executor for sync, scan orchestration, notifications, and exports |
| Engine | `engine/cmd/engine.go` | Sigma single-event matching and Flow multi-event correlation |
| Scanner | `scanner/cmd/scanner.go` | Active scanner worker that consumes Celery-compatible tasks and runs Python plugins |
| Sensor | `agent/sensor/cmd/sensor.go` | Windows service for registration, plugin control, collection, status reporting, and self-upgrade |
| Zeek | `zeek/plugins` | TrafficReceiver packet receiver and RedisWriter log writer plugins |

## Quick Takeaways

- The `ada_backend` container is not a single-process service. Supervisor runs `nginx`, `apiserver`, `task_server`, and `task_worker` together.
- `Redis` is a core middleware layer for asynchronous task broker/backend data, sensor control state, log queues, rule-engine caches, notification queues, and statistics.
- `MongoDB` is the business source of truth for users, domains, sensors, rules, scan tasks, alerts, assets, notifications, and related objects.
- `Elasticsearch` is the log and search store for eventlog, packetlog, activity, trends, and Kibana views.
- Detection has two layers: Sigma converts individual winlog/pktlog entries into activities, then Flow correlates activities within time windows into threat events.
- Active scanning does not run inside apiserver. The call chain is `apiserver -> task_server -> task_worker -> scanner(scgo) -> Python plugins`.

## Documentation Maintenance

- When architecture, ports, queues, collections, indices, or task chains change, update the corresponding document.
- Do not put production passwords, license material, tokens, or real customer domain data in documentation examples.
- Re-verify conclusions that depend on live environments. Do not rely only on old troubleshooting notes.
