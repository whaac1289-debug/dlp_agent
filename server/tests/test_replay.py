import time
from fastapi import HTTPException

from server.security import replay


class FakeRedis:
    def __init__(self):
        self.store = {}

    def exists(self, key):
        return key in self.store

    def setex(self, key, ttl, value):
        self.store[key] = value


def test_replay_protection_blocks_duplicate():
    replay.redis_client = FakeRedis()
    request_id = f"test-{time.time()}"
    timestamp = int(time.time())
    replay.replay_protection(x_nonce=request_id, x_timestamp=timestamp, x_agent_uuid="agent-1")
    try:
        replay.replay_protection(x_nonce=request_id, x_timestamp=timestamp, x_agent_uuid="agent-1")
        assert False
    except HTTPException as exc:
        assert exc.status_code == 409
