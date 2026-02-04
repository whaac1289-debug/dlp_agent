#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DLP_DATABASE_URL:-}" ]]; then
  echo "DLP_DATABASE_URL is required for backup" >&2
  exit 1
fi

output="${1:-backup_$(date +%Y%m%d_%H%M%S).sql}"
pg_dump "${DLP_DATABASE_URL}" > "${output}"
echo "Backup written to ${output}"
