#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DLP_DATABASE_URL:-}" ]]; then
  echo "DLP_DATABASE_URL is required for restore" >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: restore.sh <backup.sql>" >&2
  exit 1
fi

psql "${DLP_DATABASE_URL}" < "$1"
echo "Restore complete"
