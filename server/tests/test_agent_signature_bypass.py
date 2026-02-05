import asyncio
import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

os.environ.setdefault("DLP_ENV", "test")
os.environ.setdefault("DLP_JWT_SECRET", "bootstrap-secret-value-with-sufficient-length")
os.environ.setdefault("DLP_DATABASE_URL", "sqlite:///./bootstrap.db")
os.environ.setdefault("DLP_REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("DLP_ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("DLP_ADMIN_PASSWORD", "bootstrap-admin-password-value-strong")
os.environ.setdefault("DLP_LICENSE_KEY", "bootstrap-license")
os.environ.setdefault("DLP_ENROLLMENT_SIGNING_SECRET", "bootstrap-enrollment-signing-secret")

from server.api.v1.routes import agent as agent_routes


class DummyHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class DummyRequest:
    def __init__(self, headers=None):
        self.headers = DummyHeaders(headers or {})
        self.url = SimpleNamespace(path="/api/v1/agent/heartbeat")
        self.method = "POST"

    async def body(self):
        return b"{}"


def test_verify_agent_request_allows_dev_signature_bypass(monkeypatch):
    monkeypatch.setattr(agent_routes, "_get_agent_from_jwt", lambda _req, _db: SimpleNamespace(agent_uuid="a-1"))
    monkeypatch.setattr(agent_routes.settings, "environment", "dev")
    monkeypatch.setattr(agent_routes.settings, "dev_signature_bypass", True)

    request = DummyRequest(headers={})
    agent = asyncio.run(agent_routes._verify_agent_request(request, db=None))

    assert agent.agent_uuid == "a-1"


def test_verify_agent_request_requires_signed_headers_without_bypass(monkeypatch):
    monkeypatch.setattr(agent_routes, "_get_agent_from_jwt", lambda _req, _db: SimpleNamespace(agent_uuid="a-1"))
    monkeypatch.setattr(agent_routes.settings, "environment", "dev")
    monkeypatch.setattr(agent_routes.settings, "dev_signature_bypass", False)

    request = DummyRequest(headers={})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(agent_routes._verify_agent_request(request, db=None))

    assert exc.value.status_code == 400
    assert exc.value.detail == "missing signed headers"
