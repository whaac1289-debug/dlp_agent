from datetime import datetime
from pydantic import BaseModel


class AgentSummary(BaseModel):
    id: int
    agent_uuid: str
    hostname: str
    status: str
    last_heartbeat: datetime | None


class AlertSummary(BaseModel):
    id: int
    severity: str
    status: str
    created_at: datetime


class EventSummary(BaseModel):
    id: int
    event_type: str
    file_path: str | None
    created_at: datetime
