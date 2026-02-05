from fastapi import APIRouter
from redis import Redis
from sqlalchemy import text

from server.config import settings
from server.ingest.queue import queue
from server.models.session import SessionLocal

router = APIRouter(tags=["health"])


def _db_ok() -> bool:
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
    finally:
        db.close()


def _cache_ok() -> bool:
    try:
        redis_client = Redis.from_url(settings.redis_url)
        return redis_client.ping()
    except Exception:
        return False


def _queue_ok() -> bool:
    try:
        _ = queue.count
        return True
    except Exception:
        return False


@router.get("/health/live")
def live():
    return {"status": "ok"}


@router.get("/health/ready")
def ready():
    status = {
        "db": _db_ok(),
        "cache": _cache_ok(),
        "queue": _queue_ok(),
    }
    return {"status": "ok" if all(status.values()) else "degraded", "checks": status}
