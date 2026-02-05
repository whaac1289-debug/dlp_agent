from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from server.api.v1.api import api_router
from server.config import settings
from server.license.validator import validate_license
from server.models import models
from server.models.session import SessionLocal
from server.policy.cache import PolicyCache
from server.policy.rule_loader import iter_rules, load_rule_sets
from server.rbac.middleware import RBACMiddleware
from server.security.auth import get_password_hash
from server.security.rate_limit import RateLimitMiddleware


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, openapi_url="/api/v1/openapi.json")
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RBACMiddleware, admin_prefix=f"{settings.api_v1_prefix}/admin")

    allowed_origins = settings.allowed_origins
    if "*" in allowed_origins:
        raise RuntimeError("Wildcard CORS origins are not allowed with credentials enabled.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/metrics")
    def metrics_endpoint():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.state.policy_cache = PolicyCache()

    def _ensure_secure_defaults():
        insecure = {"change_me", "default", "password", "admin"}
        if settings.jwt_secret in insecure:
            raise RuntimeError("JWT secret must not use default values.")
        if settings.admin_password in insecure:
            raise RuntimeError("Admin password must not use default values.")
        if settings.license_key in {"replace_me", "changeme", "default"}:
            raise RuntimeError("License key must not use default values.")
        if settings.enrollment_signing_secret in insecure:
            raise RuntimeError("Enrollment signing secret must not use default values.")

    _ensure_secure_defaults()

    @app.on_event("startup")
    def seed_admin():
        license_status = validate_license()
        if not license_status.valid:
            raise RuntimeError(f"License validation failed: {license_status.reason}")
        db = SessionLocal()
        try:
            roles = {}
            for role_name in ("admin", "analyst", "viewer"):
                role = db.query(models.Role).filter_by(name=role_name).first()
                if not role:
                    role = models.Role(name=role_name)
                    db.add(role)
                    db.flush()
                roles[role_name] = role
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
                    role_id=roles["admin"].id,
                )
                db.add(user)
            if not db.query(models.Policy).filter_by(tenant_id=tenant.id).first():
                policy = models.Policy(tenant_id=tenant.id, name="Default Policy", description="Seeded policy")
                db.add(policy)
                db.flush()
                rule_sets = load_rule_sets()
                for rule in iter_rules(rule_sets):
                    db.add(models.PolicyRule(policy_id=policy.id, **rule))
            db.commit()
        finally:
            db.close()

    return app


app = create_app()
