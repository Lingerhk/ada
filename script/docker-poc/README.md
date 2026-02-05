# Docker POC Environment

## Overview
The POC environment is split across two sides:
- Portal side (cloud docker platform, `192.168.9.2`) runs `ada_portal` and provides Redis + MongoDB.
- Local side (docker-compose on `192.168.9.3`) runs the rest of the stack and hosts Elasticsearch/Kibana.

Apiserver runs twice:
- Portal-side apiserver (inside `ada_portal`).
- Backend apiserver (inside the local `ada_backend` container).

## Build Images
Local side (based on `script/docker`):
- `./build.sh build local`

Portal side:
- `./build.sh build portal`

Both:
- `./build.sh build all`

Push portal image (optional):
- `./build.sh push portal`

## Run Local Side
From `ada/script/docker-poc`:
- `docker compose up -d`
- `docker compose ps`

## Configuration Notes
- Local compose mounts POC configs from `ada-service/*.yaml` (including `scanner.yaml`).
- Redis + MongoDB are configured to `192.168.9.2`.
- Elasticsearch/Kibana are configured to `192.168.9.3`.
