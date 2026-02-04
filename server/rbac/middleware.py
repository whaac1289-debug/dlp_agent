from fastapi import Request
from jose import JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from server.security.auth import decode_access_token
from server.config import settings


class RBACMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, admin_prefix: str):
        super().__init__(app)
        self.admin_prefix = admin_prefix.rstrip("/")

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith(self.admin_prefix):
            if request.url.path.endswith("/login") or request.url.path.endswith("/refresh"):
                return await call_next(request)
            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(" ", 1)[1]
            if not token:
                token = request.cookies.get(settings.cookie_access_name)
            if not token:
                return JSONResponse({"detail": "missing token"}, status_code=401)
            try:
                payload = decode_access_token(token)
            except JWTError:
                return JSONResponse({"detail": "invalid token"}, status_code=401)
            if payload.get("role") not in {"admin", "analyst", "viewer"}:
                return JSONResponse({"detail": "invalid role"}, status_code=403)
        return await call_next(request)
