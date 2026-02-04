import pytest
from pydantic import ValidationError

from server.schemas.event import EventCreate


def test_event_requires_event_id():
    with pytest.raises(ValidationError):
        EventCreate(
            agent_uuid="agent-1",
            event_type="file_copy",
            timestamp="2024-01-01T00:00:00Z",
        )
