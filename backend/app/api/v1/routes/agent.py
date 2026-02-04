from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import secrets

from app.core.deps import get_db
from app.core.security import create_access_token
from app.core.signing import verify_signature
from app.middleware.replay import replay_protection
from app.db import models
from app.schemas.agent import AgentRegisterRequest, AgentRegisterResponse, AgentHeartbeat, AgentConfigResponse
from app.schemas.event import EventCreate
from app.services.ingestion import enqueue_event

router = APIRouter(prefix="/agent", tags=["agent"])


def _get_agent_from_jwt(request: Request, db: Session) -> models.Agent:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = auth.split(" ", 1)[1]
    try:
        payload = request.app.state.jwt_decode(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    agent_uuid = payload.get("sub")
    agent = db.query(models.Agent).filter_by(agent_uuid=agent_uuid).first()
    if not agent:
        raise HTTPException(status_code=401, detail="unknown agent")
    return agent


@router.post("/register", response_model=AgentRegisterResponse)
def register_agent(payload: AgentRegisterRequest, db: Session = Depends(get_db)):
    tenant = db.query(models.Tenant).filter_by(name=payload.tenant).first()
    if not tenant:
        tenant = models.Tenant(name=payload.tenant)
        db.add(tenant)
        db.flush()
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
    db.commit()
    token = create_access_token(payload.agent_uuid)
    return AgentRegisterResponse(agent_id=agent.id, jwt=token)


@router.post("/heartbeat")
def heartbeat(
    payload: AgentHeartbeat,
    db: Session = Depends(get_db),
    _: None = Depends(replay_protection),
):
    agent = db.query(models.Agent).filter_by(agent_uuid=payload.agent_uuid).first()
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    agent.status = payload.status
    agent.last_heartbeat = payload.timestamp
    db.commit()
    return {"status": "ok"}


@router.post("/events")
async def ingest_events(
    request: Request,
    payload: EventCreate,
    db: Session = Depends(get_db),
    _: None = Depends(replay_protection),
):
    agent = _get_agent_from_jwt(request, db)
    signature = request.headers.get("X-Signature")
    body = await request.body()
    if not signature or not verify_signature(agent.shared_secret, body, signature):
        raise HTTPException(status_code=401, detail="invalid signature")
    enqueue_event(payload.model_dump())
    return {"status": "queued"}


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
            "file_extension": rule.file_extension,
            "min_size": rule.min_size,
            "max_size": rule.max_size,
            "usb_only": rule.usb_only,
            "action": rule.action,
            "severity": rule.severity,
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
