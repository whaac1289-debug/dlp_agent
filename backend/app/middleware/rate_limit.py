import time
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from redis import Redis

from app.core.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        key = f"rate:{client_ip}:{int(time.time() / 60)}"
        count = self.redis.incr(key)
        if count == 1:
            self.redis.expire(key, 60)
        if count > settings.rate_limit_per_minute:
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return await call_next(request)
