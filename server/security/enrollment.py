import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

from server.config import settings


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def verify_enrollment_package(package_b64: str, signature: str) -> dict | None:
    try:
        payload_bytes = base64.b64decode(package_b64)
        payload = json.loads(payload_bytes.decode())
    except (ValueError, json.JSONDecodeError):
        return None
    expected = hmac.new(
        settings.enrollment_signing_secret.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    expires_at = payload.get("expires_at")
    if not expires_at:
        return None
    try:
        expires_dt = datetime.fromisoformat(expires_at)
    except ValueError:
        return None
    if expires_dt.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None
    return payload
