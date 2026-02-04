#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DLP_DATABASE_URL:-}" ]]; then
  echo "DLP_DATABASE_URL is required" >&2
  exit 1
fi

INPUT="${1:-}"
if [[ -z "$INPUT" ]]; then
  echo "Usage: $0 <backup_file.dump>" >&2
  exit 1
fi

pg_restore --clean --if-exists --dbname="$DLP_DATABASE_URL" "$INPUT"
echo "Restore completed from $INPUT"
