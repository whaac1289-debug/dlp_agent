import time
from app.middleware.replay import replay_protection
from fastapi import HTTPException


def test_replay_protection_blocks_duplicate():
    request_id = f"test-{time.time()}"
    timestamp = int(time.time())
    replay_protection(x_request_id=request_id, x_timestamp=timestamp)
    try:
        replay_protection(x_request_id=request_id, x_timestamp=timestamp)
        assert False
    except HTTPException as exc:
        assert exc.status_code == 409
