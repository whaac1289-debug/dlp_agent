import time
from dataclasses import dataclass

from server.models import models
from server.models.session import SessionLocal


@dataclass
class CachedPolicy:
    rules: list[models.PolicyRule]
    expires_at: float


class PolicyCache:
    def __init__(self, ttl_seconds: int = 60):
        self.ttl_seconds = ttl_seconds
        self._cache: dict[int, CachedPolicy] = {}

    def get_rules(self, tenant_id: int) -> list[models.PolicyRule]:
        now = time.time()
        cached = self._cache.get(tenant_id)
        if cached and cached.expires_at > now:
            return cached.rules
        db = SessionLocal()
        try:
            policy = db.query(models.Policy).filter_by(tenant_id=tenant_id, is_active=True).first()
            rules: list[models.PolicyRule] = []
            if policy:
                rules = db.query(models.PolicyRule).filter_by(policy_id=policy.id).all()
            self._cache[tenant_id] = CachedPolicy(rules=rules, expires_at=now + self.ttl_seconds)
            return rules
        finally:
            db.close()

    def invalidate(self, tenant_id: int):
        self._cache.pop(tenant_id, None)
