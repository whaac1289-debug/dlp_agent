from dataclasses import dataclass
from datetime import datetime

from server.config import settings


@dataclass
class MetricPoint:
    name: str
    value: float
    timestamp: datetime


def record_metric(name: str, value: float) -> MetricPoint | None:
    if not settings.metrics_enabled:
        return None
    return MetricPoint(name=name, value=value, timestamp=datetime.utcnow())
