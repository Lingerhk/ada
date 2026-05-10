# ADAegis

[中文版本](README_CN.md)

ADAegis is an open security platform focused on Active Directory and enterprise identity environments. It helps security teams find identity risks, collect Windows and network security telemetry, detect suspicious behavior, and investigate alerts from a single portal.

ADAegis is built for teams that need practical visibility into domain controllers, user activity, authentication behavior, network protocol traces, weak passwords, risky configurations, and identity-driven attack paths.

<p>
  <big><strong>Introduction Video:</strong> <a href="https://youtu.be/Oexs-58C-Fg" style="text-decoration: none;">https://youtu.be/Oexs-58C-Fg</a></big>
</p>
<p>
  <big><strong>Demo Portal:</strong> <a href="https://demo.adaegis.net/" style="text-decoration: none;">https://demo.adaegis.net/</a></big>
</p>

## What Problems ADAegis Solves

- Active Directory environments are difficult to observe with only endpoint or network tools.
- Security teams need AD security auditing to discover risks and guide hardening work.
- Identity attacks often span Windows events, authentication flows, network protocols, and account behavior.
- Security teams need a repeatable way to assess domain risk, validate security posture, and investigate alerts.
- Rule engineering should be close to real telemetry, not detached from what sensors can actually collect.

ADAegis brings these pieces together in one deployable stack: collection, detection, risk assessment, alert triage, and operational workflows.

## Core Highlights

- **Active Directory security focus**: built around domain assets, users, sensors, Windows events, authentication behavior, and AD-oriented risk checks.
- **Integrated telemetry**: combines Windows event logs, packet-derived protocol logs, and sensor status into a unified backend.
- **Threat detection**: supports Sigma-style single-event detection and multi-event correlation for identity attack behavior.
- **MCP protocol and AI Agent (coming soon)**: exposes security workflows through the MCP protocol; AI Agent capabilities are planned for threat detection, alert investigation, and security operations.
- **Risk assessment**: includes baseline checks, leak checks, weak-password checks, and scan task tracking.
- **Portal-first workflow**: provides a web UI for dashboard views, domain management, sensor management, scan results, rules, alerts, and reports.
- **Docker-based deployment**: ships with compose files and image build scripts for repeatable deployment.
- **Developer-friendly structure**: backend, engine, scanner, sensor, deployment scripts, and technical docs are organized in one Go repository.

## Repositories

- Backend and core services: [github.com/Lingerhk/ada](https://github.com/Lingerhk/ada)
- Frontend portal: [github.com/Lingerhk/ada-web](https://github.com/Lingerhk/ada-web)

The frontend repository should be checked out next to this repository when building the full backend image from source.

## Quick Deployment

For a standard Docker-based deployment, use the compose assets under `script/docker`.

### Prerequisites

- Docker Engine
- Docker Compose
- Linux host with enough memory for Elasticsearch and the backend services
- Prebuilt ADAegis images, or a local environment capable of building them

### Start With Existing Images

If the required images are already available on the host:

```bash
cd script/docker
docker compose up -d
docker compose ps
```

The portal is served by the backend service on port `80` by default.

### Build Images From Source

Keep the backend and frontend repositories as siblings:

```text
adaegis/
  ada/
  ada-web/
```

Then build and start the stack:

```bash
cd ada/script/docker
./build.sh build all
docker compose up -d
docker compose ps
```

If your checkout path is different from the build script's default workspace layout, update the path variables at the top of `script/docker/build.sh` before building.

## Local Development

### Backend

```bash
cd ada
go mod download
go test ./engine/sigma
go test ./engine/flow
```

Build the main backend binaries when needed:

```bash
make apiserver
make task_server
make task_worker
make engine
make scanner
```

`make apiserver` regenerates protobuf output, so make sure `protoc` and the Go protobuf plugins are installed before using that target.

### Frontend

Clone the frontend repository next to `ada`:

```bash
git clone git@github.com:Lingerhk/ada-web.git
```

See the frontend repository documentation for install, development server, and build commands:

- [github.com/Lingerhk/ada-web](https://github.com/Lingerhk/ada-web)

### Documentation

For deeper technical details, start with the documentation index and then follow the topic-specific guides:

- [Technical documentation index](docs/README.md)
- [Architecture overview](docs/01-architecture-overview.md)
- [Runtime and deployment topology](docs/02-runtime-deployment.md)
- [Collection and detection data flow](docs/03-ingestion-dataflow.md)
- [Backend API, authentication, and task scheduling](docs/04-backend-api-tasker.md)
- [Rule engine and threat detection](docs/05-rule-engine.md)
- [Windows Sensor](docs/06-windows-sensor.md)
- [Active scanner](docs/07-scanner.md)
- [Data model and storage](docs/08-data-model-storage.md)
- [Development, testing, and troubleshooting](docs/09-development-testing.md)
- [Sensor debug memo](docs/sensor-debug-memo.md)

## Reporting Issues

Please report bugs, feature requests, and documentation problems through GitHub issues:

- [github.com/Lingerhk/ada/issues](https://github.com/Lingerhk/ada/issues)

When reporting a problem, include:

- ADAegis version or commit
- Deployment mode
- Steps to reproduce
- Expected behavior
- Relevant logs or screenshots, with secrets removed

Community contact:

- Telegram group: [ADAegis Official Support](https://t.me/+6zDk06KqdpBiNjc1)

## License

ADAegis is released under the [MIT License](https://opensource.org/license/mit).

## Status

ADAegis is under active development. Interfaces, deployment scripts, and documentation may change as the project evolves.
