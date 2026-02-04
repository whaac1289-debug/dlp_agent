#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DLP_DATABASE_URL:-}" ]]; then
  echo "DLP_DATABASE_URL is required" >&2
  exit 1
fi

OUTPUT="${1:-dlp_backup_$(date +%Y%m%d_%H%M%S).dump}"
pg_dump --format=custom --file="$OUTPUT" "$DLP_DATABASE_URL"
echo "Backup written to $OUTPUT"
