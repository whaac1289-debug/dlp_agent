import time
from fastapi import Header, HTTPException
from redis import Redis

from server.config import settings

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def replay_protection(
    x_nonce: str = Header(...),
    x_timestamp: int = Header(...),
    x_agent_uuid: str | None = Header(None),
):
    now = int(time.time())
    if abs(now - x_timestamp) > settings.request_time_skew_seconds:
        raise HTTPException(status_code=400, detail="timestamp skew")
    identity = x_agent_uuid or "unknown"
    key = f"nonce:{identity}:{x_nonce}"
    if redis_client.exists(key):
        raise HTTPException(status_code=409, detail="replay detected")
    redis_client.setex(key, settings.request_time_skew_seconds, "1")
