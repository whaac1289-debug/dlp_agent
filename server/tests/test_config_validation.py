import os

import pytest

os.environ.setdefault("DLP_ENV", "test")
os.environ.setdefault("DLP_JWT_SECRET", "bootstrap-secret-value-with-sufficient-length")
os.environ.setdefault("DLP_DATABASE_URL", "sqlite:///./bootstrap.db")
os.environ.setdefault("DLP_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("DLP_ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("DLP_ADMIN_PASSWORD", "bootstrap-admin-password-value-strong")
os.environ.setdefault("DLP_LICENSE_KEY", "bootstrap-license")
os.environ.setdefault("DLP_ENROLLMENT_SIGNING_SECRET", "bootstrap-enrollment-signing-secret")

from server.config.base import BaseConfig


def _base_kwargs(**overrides):
    data = {
        "jwt_secret": "x" * 24,
        "database_url": "sqlite:///./test.db",
        "redis_url": "redis://localhost:6379/0",
        "admin_email": "admin@example.com",
        "admin_password": "y" * 24,
        "license_key": "license-key",
        "enrollment_signing_secret": "z" * 24,
        "allowed_origins": ["http://localhost:3000"],
    }
    data.update(overrides)
    return data


def test_rejects_short_sensitive_values():
    with pytest.raises(ValueError):
        BaseConfig(**_base_kwargs(jwt_secret="short"))


def test_rejects_invalid_origin_scheme():
    with pytest.raises(ValueError):
        BaseConfig(**_base_kwargs(allowed_origins=["ftp://example.com"]))


def test_prod_rejects_plain_http_origin():
    with pytest.raises(ValueError):
        BaseConfig(
            **_base_kwargs(
                environment="prod",
                allowed_origins=["http://example.com"],
            )
        )
