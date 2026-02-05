from datetime import datetime

from pydantic import BaseModel


class EnrollmentTokenCreate(BaseModel):
    tenant: str
    agent_uuid: str | None = None
    expires_at: datetime | None = None


class EnrollmentTokenResponse(BaseModel):
    token: str
    expires_at: datetime
