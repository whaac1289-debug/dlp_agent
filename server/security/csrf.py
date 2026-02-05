import secrets

from fastapi import Header, HTTPException, Request

from server.config import settings


def set_csrf_cookie(response) -> str:
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        settings.csrf_cookie_name,
        token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    return token


def csrf_protect(request: Request, x_csrf_token: str | None = Header(None)):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    if not cookie_token or not x_csrf_token or cookie_token != x_csrf_token:
        raise HTTPException(status_code=403, detail="csrf validation failed")
