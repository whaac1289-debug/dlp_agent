import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from server.config import settings
from server.ingest.queue import enqueue_event, process_event_with_session
from server.metrics.collector import metrics
from server.models import models
from server.schemas.agent import (
    AgentConfigResponse,
    AgentHeartbeat,
    AgentRegisterRequest,
    AgentRegisterResponse,
)
from server.schemas.event import EventBatchCreate, EventCreate
from server.security.auth import create_agent_token, decode_agent_token
from server.security.deps import get_db
from server.security.enrollment import hash_token, verify_enrollment_package
from server.security.replay import replay_protection
from server.security.signing import verify_signature

router = APIRouter(prefix="/agent", tags=["agent"])


def _get_agent_from_jwt(request: Request, db: Session) -> models.Agent:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = auth.split(" ", 1)[1]
    try:
        payload = decode_agent_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    agent_uuid = payload.get("sub")
    agent = db.query(models.Agent).filter_by(agent_uuid=agent_uuid).first()
    if not agent:
        raise HTTPException(status_code=401, detail="unknown agent")
    return agent


async def _verify_agent_request(request: Request, db: Session) -> models.Agent:
    agent = _get_agent_from_jwt(request, db)
    signature = request.headers.get("X-Signature")
    timestamp = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    protocol_version = request.headers.get("X-Agent-Protocol-Version")
    if not all([signature, timestamp, nonce, protocol_version]):
        raise HTTPException(status_code=400, detail="missing signed headers")
    if protocol_version not in settings.agent_protocol_versions:
        raise HTTPException(status_code=400, detail="unsupported protocol")
    try:
        timestamp_int = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid timestamp")
    replay_protection(x_nonce=nonce, x_timestamp=timestamp_int, x_agent_uuid=agent.agent_uuid)
    body = await request.body()
    if not verify_signature(
        agent.shared_secret,
        body,
        timestamp,
        nonce,
        request.url.path,
        request.method,
        signature,
    ):
        raise HTTPException(status_code=401, detail="invalid signature")
    return agent


@router.post("/register", response_model=AgentRegisterResponse)
def register_agent(payload: AgentRegisterRequest, db: Session = Depends(get_db)):
    enrollment_record = None
    if payload.enrollment_token:
        token_hash = hash_token(payload.enrollment_token)
        enrollment_record = db.query(models.EnrollmentToken).filter_by(token_hash=token_hash).first()
        if (
            not enrollment_record
            or enrollment_record.used_at
            or enrollment_record.expires_at < datetime.utcnow()
        ):
            raise HTTPException(status_code=401, detail="invalid enrollment token")
    elif payload.enrollment_package and payload.enrollment_signature:
        package = verify_enrollment_package(payload.enrollment_package, payload.enrollment_signature)
        if not package:
            raise HTTPException(status_code=401, detail="invalid enrollment package")
        if package.get("agent_uuid") != payload.agent_uuid or package.get("tenant") != payload.tenant:
            raise HTTPException(status_code=400, detail="enrollment package mismatch")
    else:
        raise HTTPException(status_code=401, detail="enrollment required")
    tenant = db.query(models.Tenant).filter_by(name=payload.tenant).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")
    if enrollment_record:
        if enrollment_record.tenant_id != tenant.id:
            raise HTTPException(status_code=401, detail="enrollment token tenant mismatch")
        if enrollment_record.agent_uuid and enrollment_record.agent_uuid != payload.agent_uuid:
            raise HTTPException(status_code=401, detail="enrollment token bound to different agent")
    existing = db.query(models.Agent).filter_by(agent_uuid=payload.agent_uuid).first()
    shared_secret = secrets.token_hex(32)
    if existing:
        existing.fingerprint = payload.fingerprint
        existing.hostname = payload.hostname
        existing.ip_address = payload.ip_address
        existing.version = payload.version
        existing.shared_secret = shared_secret
        agent = existing
    else:
        agent = models.Agent(
            tenant_id=tenant.id,
            agent_uuid=payload.agent_uuid,
            fingerprint=payload.fingerprint,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            version=payload.version,
            status="online",
            shared_secret=shared_secret,
        )
        db.add(agent)
    if enrollment_record:
        enrollment_record.used_at = datetime.utcnow()
        enrollment_record.agent_uuid = payload.agent_uuid
    db.add(
        models.AuditLog(
            tenant_id=tenant.id,
            user_id=None,
            action="agent_enroll",
            details={"agent_uuid": payload.agent_uuid, "hostname": payload.hostname},
        )
    )
    db.commit()
    token = create_agent_token(payload.agent_uuid)
    return AgentRegisterResponse(agent_id=agent.id, jwt=token)


@router.post("/heartbeat")
async def heartbeat(
    payload: AgentHeartbeat,
    request: Request,
    db: Session = Depends(get_db),
):
    agent = await _verify_agent_request(request, db)
    if agent.agent_uuid != payload.agent_uuid:
        raise HTTPException(status_code=400, detail="agent mismatch")
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    agent.status = payload.status
    agent.last_heartbeat = payload.timestamp
    db.commit()
    if payload.status == "online":
        metrics.agent_online_count.inc()
    return {"status": "ok"}


@router.post("/events")
async def ingest_events(
    request: Request,
    payload: EventCreate,
    db: Session = Depends(get_db),
):
    agent = await _verify_agent_request(request, db)
    if payload.agent_uuid != agent.agent_uuid:
        raise HTTPException(status_code=400, detail="agent mismatch")
    enqueue_event(payload.model_dump())
    return {"status": "queued"}


@router.post("/events/batch")
async def ingest_events_batch(
    request: Request,
    payload: EventBatchCreate,
    db: Session = Depends(get_db),
):
    agent = await _verify_agent_request(request, db)
    report = {"accepted": [], "rejected": []}
    for event in payload.events:
        if event.agent_uuid != agent.agent_uuid:
            report["rejected"].append({"event_id": event.event_id, "reason": "agent mismatch"})
            continue
        try:
            with db.begin_nested():
                status, reason = process_event_with_session(db, event.model_dump())
                if status == "accepted":
                    report["accepted"].append(event.event_id)
                elif status == "duplicate":
                    report["rejected"].append({"event_id": event.event_id, "reason": "duplicate"})
                else:
                    report["rejected"].append({"event_id": event.event_id, "reason": reason or "rejected"})
        except Exception as exc:
            report["rejected"].append({"event_id": event.event_id, "reason": str(exc)})
    db.commit()
    return report


@router.get("/policy", response_model=list[dict])
def get_policy(request: Request, db: Session = Depends(get_db)):
    agent = _get_agent_from_jwt(request, db)
    policy = db.query(models.Policy).filter_by(tenant_id=agent.tenant_id, is_active=True).first()
    if not policy:
        return []
    rules = db.query(models.PolicyRule).filter_by(policy_id=policy.id).all()
    return [
        {
            "id": rule.id,
            "type": rule.rule_type,
            "pattern": rule.pattern,
            "keywords": rule.keywords,
            "hashes": rule.hashes,
            "file_extension": rule.file_extension,
            "min_size": rule.min_size,
            "max_size": rule.max_size,
            "usb_only": rule.usb_only,
            "action": rule.action,
            "severity": rule.severity,
            "severity_score": rule.severity_score,
            "tags": rule.tags,
            "is_whitelist": rule.is_whitelist,
            "priority": rule.priority,
        }
        for rule in rules
    ]


@router.get("/config", response_model=AgentConfigResponse)
def get_config(request: Request, db: Session = Depends(get_db)):
    agent = _get_agent_from_jwt(request, db)
    config = (
        db.query(models.AgentConfig)
        .filter_by(agent_id=agent.id)
        .order_by(models.AgentConfig.config_version.desc())
        .first()
    )
    if not config:
        config = models.AgentConfig(agent_id=agent.id, config_version=1, config={"scan_interval": 60})
        db.add(config)
        db.commit()
    return AgentConfigResponse(config_version=config.config_version, config=config.config)
