from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.responses import StreamingResponse
import csv
import io
import secrets
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from jose import JWTError

from server.security.deps import get_current_user
from server.security.auth import create_access_token, create_refresh_token, verify_password, decode_refresh_token
from server.config import settings
from server.models import models
from server.models.session import get_db
from server.schemas.auth import LoginRequest, Token, RefreshRequest
from server.schemas.admin import AgentSummary, EventSummary, AlertSummary
from server.schemas.policy import PolicyCreate
from server.schemas.enrollment import EnrollmentTokenCreate, EnrollmentTokenResponse
from server.security.csrf import csrf_protect, set_csrf_cookie
from server.rbac.deps import require_roles
from server.security.enrollment import hash_token
from server.metrics.collector import metrics

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            db.add(models.LoginHistory(user_id=user.id, success=False, ip_address=request.client.host))
            db.commit()
        metrics.auth_failures.inc()
        raise HTTPException(status_code=401, detail="invalid credentials")
    db.add(models.LoginHistory(user_id=user.id, success=True, ip_address=request.client.host))
    db.add(
        models.AuditLog(
            tenant_id=user.tenant_id,
            user_id=user.id,
            action="login",
            details={"email": user.email},
        )
    )
    db.commit()
    access = create_access_token(str(user.id), user.tenant_id, user.role.name)
    refresh = create_refresh_token(str(user.id), user.tenant_id, user.role.name)
    response.set_cookie(
        settings.cookie_access_name,
        access,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    response.set_cookie(
        settings.cookie_refresh_name,
        refresh,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    set_csrf_cookie(response)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=Token, dependencies=[Depends(csrf_protect)])
def refresh(payload: RefreshRequest, response: Response):
    try:
        decoded = decode_refresh_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid refresh token")
    access = create_access_token(decoded.get("sub"), decoded.get("tenant_id"), decoded.get("role"))
    refresh_token = create_refresh_token(decoded.get("sub"), decoded.get("tenant_id"), decoded.get("role"))
    response.set_cookie(
        settings.cookie_access_name,
        access,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    response.set_cookie(
        settings.cookie_refresh_name,
        refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    set_csrf_cookie(response)
    return Token(access_token=access, refresh_token=refresh_token)


@router.get("/agents", response_model=list[AgentSummary], dependencies=[Depends(require_roles("admin", "analyst", "viewer"))])
def list_agents(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    agents = db.query(models.Agent).filter_by(tenant_id=user.tenant_id).all()
    return [
        AgentSummary(
            id=agent.id,
            agent_uuid=agent.agent_uuid,
            hostname=agent.hostname,
            status=agent.status,
            last_heartbeat=agent.last_heartbeat,
        )
        for agent in agents
    ]


@router.get("/events", response_model=list[EventSummary], dependencies=[Depends(require_roles("admin", "analyst", "viewer"))])
def list_events(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    events = (
        db.query(models.Event)
        .filter_by(tenant_id=user.tenant_id)
        .order_by(models.Event.created_at.desc())
        .limit(200)
        .all()
    )
    return [
        EventSummary(
            id=event.id,
            event_type=event.event_type,
            file_path=event.file_path,
            created_at=event.created_at,
        )
        for event in events
    ]


@router.get("/alerts", response_model=list[AlertSummary], dependencies=[Depends(require_roles("admin", "analyst", "viewer"))])
def list_alerts(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    alerts = (
        db.query(models.Alert)
        .filter_by(tenant_id=user.tenant_id)
        .order_by(models.Alert.created_at.desc())
        .limit(200)
        .all()
    )
    return [
        AlertSummary(
            id=alert.id,
            severity=alert.severity,
            status=alert.status,
            created_at=alert.created_at,
        )
        for alert in alerts
    ]


@router.get("/events/export", dependencies=[Depends(require_roles("admin", "analyst"))])
def export_events(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    events = db.query(models.Event).filter_by(tenant_id=user.tenant_id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "event_type", "file_path", "file_hash", "file_size", "created_at"])
    for event in events:
        writer.writerow([event.id, event.event_type, event.file_path, event.file_hash, event.file_size, event.created_at])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv")


@router.post("/policies", dependencies=[Depends(require_roles("admin")), Depends(csrf_protect)])
def create_policy(
    payload: PolicyCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    policy = models.Policy(
        tenant_id=user.tenant_id,
        name=payload.name,
        description=payload.description,
    )
    db.add(policy)
    db.flush()
    for rule in payload.rules:
        db.add(
            models.PolicyRule(
                policy_id=policy.id,
                rule_type=rule.rule_type,
                pattern=rule.pattern,
                keywords=rule.keywords,
                hashes=rule.hashes,
                file_extension=rule.file_extension,
                min_size=rule.min_size,
                max_size=rule.max_size,
                usb_only=rule.usb_only,
                action=rule.action,
                severity=rule.severity,
                severity_score=rule.severity_score,
                tags=rule.tags,
                is_whitelist=rule.is_whitelist,
                priority=rule.priority,
            )
        )
    db.add(
        models.AuditLog(
            tenant_id=user.tenant_id,
            user_id=user.id,
            action="create_policy",
            details={"policy_name": payload.name},
        )
    )
    db.commit()
    request.app.state.policy_cache.invalidate(user.tenant_id)
    return {"id": policy.id, "version": policy.version}


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenResponse,
    dependencies=[Depends(require_roles("admin")), Depends(csrf_protect)],
)
def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    tenant = db.query(models.Tenant).filter_by(name=payload.tenant).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")
    token = secrets.token_urlsafe(32)
    expires_at = payload.expires_at or (datetime.utcnow() + timedelta(hours=settings.enrollment_token_ttl_hours))
    record = models.EnrollmentToken(
        tenant_id=tenant.id,
        token_hash=hash_token(token),
        agent_uuid=payload.agent_uuid,
        expires_at=expires_at,
    )
    db.add(record)
    db.add(
        models.AuditLog(
            tenant_id=tenant.id,
            user_id=user.id,
            action="create_enrollment_token",
            details={"agent_uuid": payload.agent_uuid, "expires_at": expires_at.isoformat()},
        )
    )
    db.commit()
    return EnrollmentTokenResponse(token=token, expires_at=expires_at)


@router.post(
    "/rotate-secrets",
    dependencies=[Depends(require_roles("admin")), Depends(csrf_protect)],
)
def rotate_secrets(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    new_jwt_secret = secrets.token_urlsafe(48)
    new_enrollment_secret = secrets.token_urlsafe(48)
    db.add(
        models.AuditLog(
            tenant_id=user.tenant_id,
            user_id=user.id,
            action="rotate_secrets",
            details={"jwt_secret_rotated": True, "enrollment_secret_rotated": True},
        )
    )
    db.commit()
    return {"jwt_secret": new_jwt_secret, "enrollment_signing_secret": new_enrollment_secret}
