from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt

from server.api.v1.api import api_router
from server.config import settings
from server.security.auth import get_password_hash
from server.models import models
from server.models.session import SessionLocal
from server.security.rate_limit import RateLimitMiddleware
from server.license.validator import validate_license


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, openapi_url="/api/v1/openapi.json")
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    def _jwt_decode(token: str):
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])

    app.state.jwt_decode = _jwt_decode

    @app.on_event("startup")
    def seed_admin():
        license_status = validate_license()
        if not license_status.valid:
            raise RuntimeError(f"License validation failed: {license_status.reason}")
        db = SessionLocal()
        try:
            role = db.query(models.Role).filter_by(name="admin").first()
            if not role:
                role = models.Role(name="admin")
                db.add(role)
                db.flush()
            tenant = db.query(models.Tenant).filter_by(name="default").first()
            if not tenant:
                tenant = models.Tenant(name="default")
                db.add(tenant)
                db.flush()
            user = db.query(models.User).filter_by(email=settings.admin_email).first()
            if not user:
                user = models.User(
                    tenant_id=tenant.id,
                    email=settings.admin_email,
                    password_hash=get_password_hash(settings.admin_password),
                    role_id=role.id,
                )
                db.add(user)
            db.commit()
        finally:
            db.close()

    return app


app = create_app()
