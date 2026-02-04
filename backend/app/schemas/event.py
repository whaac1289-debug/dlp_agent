from datetime import datetime
from pydantic import BaseModel


class EventCreate(BaseModel):
    agent_uuid: str
    event_type: str
    file_path: str | None = None
    file_hash: str | None = None
    file_size: int | None = None
    metadata: dict | None = None
    user_context: dict | None = None
    timestamp: datetime
