from dataclasses import dataclass
from datetime import datetime

from prometheus_client import Counter, Gauge

from server.config import settings


@dataclass
class MetricPoint:
    name: str
    value: float
    timestamp: datetime


class Metrics:
    def __init__(self):
        self.ingest_total = Counter("dlp_ingest_total", "Total ingested events")
        self.detection_hits = Counter("dlp_detection_hits_total", "Total detection hits")
        self.auth_failures = Counter("dlp_auth_failures_total", "Total auth failures")
        self.agent_online_count = Gauge("dlp_agent_online", "Agents online")


metrics = Metrics()


def record_metric(name: str, value: float) -> MetricPoint | None:
    if not settings.metrics_enabled:
        return None
    return MetricPoint(name=name, value=value, timestamp=datetime.utcnow())
