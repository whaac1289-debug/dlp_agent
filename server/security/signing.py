import hashlib
import hmac


def build_signature_payload(
    body: bytes,
    timestamp: str,
    nonce: str,
    path: str,
    method: str,
) -> bytes:
    canonical = "\n".join([method.upper(), path, timestamp, nonce]).encode()
    return canonical + b"\n" + body


def sign_payload(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def sign_request(
    secret: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    path: str,
    method: str,
) -> str:
    payload = build_signature_payload(body, timestamp, nonce, path, method)
    return sign_payload(secret, payload)


def verify_signature(
    secret: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    path: str,
    method: str,
    signature: str,
) -> bool:
    expected = sign_request(secret, body, timestamp, nonce, path, method)
    return hmac.compare_digest(expected, signature)
