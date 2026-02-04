import time
from fastapi import Header, HTTPException
from redis import Redis

from app.core.config import settings

redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def replay_protection(
    x_request_id: str = Header(...),
    x_timestamp: int = Header(...),
):
    now = int(time.time())
    if abs(now - x_timestamp) > settings.request_time_skew_seconds:
        raise HTTPException(status_code=400, detail="timestamp skew")
    key = f"nonce:{x_request_id}"
    if redis_client.exists(key):
        raise HTTPException(status_code=409, detail="replay detected")
    redis_client.setex(key, settings.request_time_skew_seconds, "1")
