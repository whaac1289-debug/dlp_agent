# Deployment Guide

## Prerequisites
- Docker + Docker Compose
- TLS certificates at `deploy/nginx/certs/server.crt` and `deploy/nginx/certs/server.key`

## Environment configuration
1. Copy `server/.env.example` to `.env` and populate required `DLP_` variables.
2. Ensure `DLP_LICENSE_KEY` is valid for the target environment.

## Docker deployment
```bash
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

## Database migrations
```bash
docker compose -f deploy/docker/docker-compose.yml run --rm server \
  alembic -c server/alembic.ini upgrade head
```

## Access endpoints
- Dashboard: `https://localhost/`
- API: `https://localhost/api/v1`
