#!/usr/bin/env bash
set -euo pipefail

generate_secret() {
  python - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
}

echo "DLP_JWT_SECRET=$(generate_secret)"
echo "DLP_ADMIN_PASSWORD=$(generate_secret)"
echo "DLP_ENROLLMENT_SIGNING_SECRET=$(generate_secret)"
