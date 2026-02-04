from sqlalchemy.orm import Session
from rq import Queue
from redis import Redis

from app.core.config import settings
from app.db import models
from app.services.policy_engine import PolicyEngine
from app.services.siem import send_syslog

redis_conn = Redis.from_url(settings.redis_url)
queue = Queue("events", connection=redis_conn)


def enqueue_event(event_data: dict):
    queue.enqueue(process_event, event_data)


def process_event(event_data: dict):
    from app.db.session import SessionLocal

    db: Session = SessionLocal()
    try:
        agent = db.query(models.Agent).filter_by(agent_uuid=event_data["agent_uuid"]).first()
        if not agent:
            return
        event = models.Event(
            tenant_id=agent.tenant_id,
            agent_id=agent.id,
            event_type=event_data["event_type"],
            file_path=event_data.get("file_path"),
            file_hash=event_data.get("file_hash"),
            file_size=event_data.get("file_size"),
            metadata=event_data.get("metadata"),
            user_context=event_data.get("user_context"),
        )
        db.add(event)
        db.flush()

        policy = db.query(models.Policy).filter_by(tenant_id=agent.tenant_id, is_active=True).first()
        rules = []
        if policy:
            rules = db.query(models.PolicyRule).filter_by(policy_id=policy.id).all()
        engine = PolicyEngine(rules)
        decision = engine.evaluate(event_data)
        if decision.decision in {"alert", "block"}:
            alert = models.Alert(
                tenant_id=agent.tenant_id,
                event_id=event.id,
                rule_id=decision.rule_id,
                severity=decision.severity,
                status="open",
                escalated=decision.decision == "block",
            )
            db.add(alert)
            send_syslog(
                {
                    "agent_uuid": agent.agent_uuid,
                    "event_type": event.event_type,
                    "decision": decision.decision,
                    "severity": decision.severity,
                }
            )
        db.commit()
    finally:
        db.close()
