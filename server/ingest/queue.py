from sqlalchemy.orm import Session
from rq import Queue
from redis import Redis

from server.config import settings
from server.models import models
from server.policy.engine import PolicyEngine
from server.policy.cache import PolicyCache
from server.detection.pipeline import run_detection
from server.metrics.collector import record_metric, metrics
from server.siem.exporter import send_syslog

redis_conn = Redis.from_url(settings.redis_url)
queue = Queue("events", connection=redis_conn)
policy_cache = PolicyCache()


def enqueue_event(event_data: dict):
    queue.enqueue(process_event, event_data)


def process_event_with_session(db: Session, event_data: dict) -> tuple[str, str | None]:
    agent = db.query(models.Agent).filter_by(agent_uuid=event_data["agent_uuid"]).first()
    if not agent:
        return "rejected", "unknown agent"
    existing = db.query(models.Event).filter_by(event_id=event_data["event_id"]).first()
    if existing:
        return "duplicate", None
    event = models.Event(
        event_id=event_data["event_id"],
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

    rules = policy_cache.get_rules(agent.tenant_id)
    engine = PolicyEngine(rules)
    decision = engine.evaluate(event_data)
    if decision.decision == "allow" and decision.reason.startswith("Matched whitelist"):
        record_metric("dlp.ingest.event", 1)
        metrics.ingest_total.inc()
        return "accepted", None
    findings_report = run_detection(event_data, rules)
    record_metric("dlp.ingest.event", 1)
    metrics.ingest_total.inc()
    if decision.decision in {"alert", "block"}:
        alert = models.Alert(
            tenant_id=agent.tenant_id,
            event_id=event.id,
            rule_id=decision.rule_id,
            severity=decision.severity or findings_report.severity,
            status="open",
            escalated=decision.decision == "block",
        )
        db.add(alert)
        metrics.detection_hits.inc()
        send_syslog(
            {
                "agent_uuid": agent.agent_uuid,
                "event_type": event.event_type,
                "decision": decision.decision,
                "severity": decision.severity,
                "findings": [finding.detector for finding in findings_report.findings],
            }
        )
    return "accepted", None


def process_event(event_data: dict):
    from server.models.session import SessionLocal

    db: Session = SessionLocal()
    try:
        process_event_with_session(db, event_data)
        db.commit()
    finally:
        db.close()
