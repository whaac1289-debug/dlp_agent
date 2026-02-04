from server.security.signing import sign_request, verify_signature


def test_signature_verification():
    secret = "secret"
    body = b'{"test": 1}'
    signature = sign_request(secret, body, "1700000000", "nonce-1", "/api/v1/agent/events", "POST")
    assert verify_signature(
        secret,
        body,
        "1700000000",
        "nonce-1",
        "/api/v1/agent/events",
        "POST",
        signature,
    )
