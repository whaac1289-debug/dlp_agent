#!/usr/bin/env bash
set -euo pipefail

echo "Starting DLP server..."
PYTHONPATH=. uvicorn server.main:app --host 0.0.0.0 --port 8000
