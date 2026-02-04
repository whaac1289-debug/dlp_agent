from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
import csv
import io
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from server.security.deps import get_current_user
from server.security.auth import create_access_token, create_refresh_token, verify_password
from server.config import settings
from server.models import models
from server.models.session import get_db
from server.schemas.auth import LoginRequest, Token, RefreshRequest
from server.schemas.admin import AgentSummary, EventSummary, AlertSummary
from server.schemas.policy import PolicyCreate

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            db.add(models.LoginHistory(user_id=user.id, success=False))
            db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")
    db.add(models.LoginHistory(user_id=user.id, success=True))
    db.commit()
    access = create_access_token(str(user.id))
    refresh = create_refresh_token(str(user.id))
    return Token(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=Token)
def refresh(payload: RefreshRequest):
    try:
        decoded = jwt.decode(payload.refresh_token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid refresh token")
    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="invalid token type")
    access = create_access_token(decoded.get("sub"))
    refresh_token = create_refresh_token(decoded.get("sub"))
    return Token(access_token=access, refresh_token=refresh_token)


@router.get("/agents", response_model=list[AgentSummary])
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


@router.get("/events", response_model=list[EventSummary])
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


@router.get("/alerts", response_model=list[AlertSummary])
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


@router.get("/events/export")
def export_events(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    events = db.query(models.Event).filter_by(tenant_id=user.tenant_id).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "event_type", "file_path", "file_hash", "file_size", "created_at"])
    for event in events:
        writer.writerow([event.id, event.event_type, event.file_path, event.file_hash, event.file_size, event.created_at])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv")


@router.post("/policies")
def create_policy(
    payload: PolicyCreate,
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
                file_extension=rule.file_extension,
                min_size=rule.min_size,
                max_size=rule.max_size,
                usb_only=rule.usb_only,
                action=rule.action,
                severity=rule.severity,
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
    return {"id": policy.id, "version": policy.version}
