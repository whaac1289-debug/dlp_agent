import importlib
from datetime import datetime, timedelta

from jose import JWTError, jwt


def _reload_settings(monkeypatch):
    monkeypatch.setenv("DLP_ENV", "test")
    monkeypatch.setenv("DLP_JWT_SECRET", "test-secret")
    monkeypatch.setenv("DLP_DATABASE_URL", "sqlite://")
    monkeypatch.setenv("DLP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("DLP_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("DLP_ADMIN_PASSWORD", "Admin-Password-123!")
    monkeypatch.setenv("DLP_LICENSE_KEY", "license-test")
    monkeypatch.setenv("DLP_ENROLLMENT_SIGNING_SECRET", "enroll-secret")
    import server.config
    import server.security.auth

    importlib.reload(server.config)
    importlib.reload(server.security.auth)
    return server.config.settings, server.security.auth


def test_wrong_issuer_rejected(monkeypatch):
    settings, auth = _reload_settings(monkeypatch)
    payload = {
        "sub": "1",
        "exp": datetime.utcnow() + timedelta(minutes=5),
        "iss": "wrong-issuer",
        "aud": settings.jwt_audience,
        "token_type": settings.jwt_access_token_type,
        "tenant_id": 1,
        "role": "admin",
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    try:
        auth.decode_access_token(token)
        assert False
    except JWTError:
        assert True


def test_expired_token_rejected(monkeypatch):
    settings, auth = _reload_settings(monkeypatch)
    payload = {
        "sub": "1",
        "exp": datetime.utcnow() - timedelta(minutes=1),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "token_type": settings.jwt_access_token_type,
        "tenant_id": 1,
        "role": "admin",
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    try:
        auth.decode_access_token(token)
        assert False
    except JWTError:
        assert True
