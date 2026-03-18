# ADA Backend

`ada` is the backend and engine repository for ADAegis. The main areas are:

- `backend/apiserver`: gRPC API, authentication, system management, WebSSH, and Kibana proxy.
- `backend/tasker`: scheduled jobs, rule sync, scan orchestration, notifications, and reports.
- `engine`: threat and behavior rule engine.
- `scanner`: risk scanning and AD-related checks.
- `agent`: sensor packages and install/upgrade tooling.
- `infra`: shared Mongo, Redis, logging, crypto, and file utilities.

## Entry Points

- API server: `backend/apiserver/cmd/apiserver.go`
- Task server: `backend/tasker/cmd/server/main.go`
- Task worker: `backend/tasker/cmd/worker/main.go`
- Engine: `engine/cmd/engine.go`
- Scanner: `scanner/cmd/scanner.go`

## Common Commands

```bash
go test ./infra/loghook
go test ./backend/tasker/worker -run '^$'
make apiserver
make task_server
make task_worker
make engine
make scanner
```

## Related Docs

- Repository overview: [`../README.md`](../README.md)
- Architecture: [`../docs/architecture.md`](../docs/architecture.md)
- Local development: [`../docs/local-development.md`](../docs/local-development.md)
