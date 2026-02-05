from datetime import datetime

from pydantic import BaseModel, Field


class AgentRegisterRequest(BaseModel):
    agent_uuid: str = Field(..., max_length=64)
    fingerprint: str
    hostname: str
    ip_address: str
    version: str
    tenant: str
    enrollment_token: str | None = None
    enrollment_package: str | None = None
    enrollment_signature: str | None = None


class AgentRegisterResponse(BaseModel):
    agent_id: int
    jwt: str


class AgentHeartbeat(BaseModel):
    agent_uuid: str
    timestamp: datetime
    status: str


class AgentConfigResponse(BaseModel):
    config_version: int
    config: dict
