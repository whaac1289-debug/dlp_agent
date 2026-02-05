# DLP Platform

Enterprise DLP platform with a Windows endpoint agent, FastAPI control plane, and React dashboard.

## Repository layout

- `agent/` — endpoint service and enforcement components.
- `server/` — API, ingest pipeline, policy engine, and security controls.
- `dashboard/` — operator UI.
- `deploy/` — Docker Compose and Kubernetes manifests.
- `rules/` — policy rule packs.
- `tests/` and `server/tests/` — automated tests.

## Build prerequisites

### Common

1. Git
2. Python 3.11+
3. `pip`
4. Docker + Docker Compose plugin (for containerized local stack)

### Agent build (Windows only)

1. Windows 10/11 or Windows Server build host
2. MSYS2/MinGW or equivalent GNU C++ toolchain with Windows SDK headers (`windows.h`)
3. `libcurl`, `sqlite3`, and required Windows link libraries

## Exact local build and test steps

### 1) Install server dependencies

```bash
python -m pip install -r server/requirements.txt
```

### 2) Run server tests

```bash
PYTHONPATH=. pytest server/tests
```

### 3) Build agent binary (Windows host)

```bash
make agent-build
```

On non-Windows hosts, `make agent-build` is intentionally skipped with a clear message.

### 4) Run all tests via Make

```bash
make test
```

This always runs server tests; agent tests run only on Windows hosts.

## Reproducible dependency build

- Python server dependencies are pinned in `server/requirements.txt`.
- A full environment lock snapshot can be generated with:

```bash
make lockfile
```

This writes a sorted `server/requirements.lock` for repeatable environment recreation.

## Containerized local stack

```bash
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

Run DB migrations:

```bash
docker compose -f deploy/docker/docker-compose.yml run --rm server \
  alembic -c server/alembic.ini upgrade head
```

## Configuration schema

- Agent config JSON schema: `agent/config/agent_config.schema.json`.
- Validate `agent/config/agent_config.json` against the schema in CI or pre-deploy checks.

## Development-mode signature bypass

For local development only, the server supports bypassing agent request HMAC signature checks:

- Config key: `DLP_DEV_SIGNATURE_BYPASS=true`
- Scope: active only when `DLP_ENV=dev`
- Authentication requirement remains: agent JWT is still required

Do **not** enable this in production.

## Security and operational notes

- Keep `DLP_JWT_SECRET`, `DLP_ENROLLMENT_SIGNING_SECRET`, and agent shared secrets private.
- Enforce HTTPS in production for API and dashboard origins.
- Keep policy, telemetry, and signing settings aligned between server and agent.
