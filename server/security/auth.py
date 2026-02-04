from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext

from server.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _build_token(
    subject: str,
    token_type: str,
    expires_minutes: int,
    audience: str,
    tenant_id: int | None = None,
    role: str | None = None,
) -> str:
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {
        "sub": subject,
        "exp": expire,
        "iss": settings.jwt_issuer,
        "aud": audience,
        "token_type": token_type,
    }
    if tenant_id is not None:
        to_encode["tenant_id"] = tenant_id
    if role is not None:
        to_encode["role"] = role
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(
    subject: str,
    tenant_id: int,
    role: str,
    expires_minutes: int | None = None,
) -> str:
    ttl = expires_minutes or settings.jwt_exp_minutes
    return _build_token(
        subject,
        settings.jwt_access_token_type,
        ttl,
        settings.jwt_audience,
        tenant_id=tenant_id,
        role=role,
    )


def create_refresh_token(subject: str, tenant_id: int, role: str) -> str:
    return _build_token(
        subject,
        settings.jwt_refresh_token_type,
        settings.jwt_refresh_exp_minutes,
        settings.jwt_audience,
        tenant_id=tenant_id,
        role=role,
    )


def create_agent_token(subject: str) -> str:
    return _build_token(
        subject,
        settings.jwt_agent_token_type,
        settings.jwt_exp_minutes,
        settings.jwt_agent_audience,
    )


def decode_token(token: str, audience: str) -> dict:
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        audience=audience,
    )


def decode_access_token(token: str) -> dict:
    payload = decode_token(token, settings.jwt_audience)
    if payload.get("token_type") != settings.jwt_access_token_type:
        raise JWTError("invalid token type")
    return payload


def decode_refresh_token(token: str) -> dict:
    payload = decode_token(token, settings.jwt_audience)
    if payload.get("token_type") != settings.jwt_refresh_token_type:
        raise JWTError("invalid token type")
    return payload


def decode_agent_token(token: str) -> dict:
    payload = decode_token(token, settings.jwt_agent_audience)
    if payload.get("token_type") != settings.jwt_agent_token_type:
        raise JWTError("invalid token type")
    return payload


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
