# Deployment Guide

## Prerequisites
- Docker + Docker Compose
- TLS certificates placed in `deploy/nginx/certs/server.crt` and `deploy/nginx/certs/server.key`

## Steps
1. Update secrets in `.env` and `docker-compose.yml`.
2. Run migrations:
   ```bash
   docker compose run --rm backend alembic upgrade head
   ```
3. Start the stack:
   ```bash
   docker compose up -d --build
   ```
4. Access UI at `https://localhost/` and API at `https://localhost/api/v1`.
