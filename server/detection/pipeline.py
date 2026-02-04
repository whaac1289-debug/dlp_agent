from dataclasses import dataclass


@dataclass
class DetectionFinding:
    detector: str
    severity: str
    detail: str


def run_detection(event_payload: dict) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    if event_payload.get("metadata", {}).get("entropy_score"):
        findings.append(
            DetectionFinding(
                detector="entropy",
                severity="medium",
                detail="entropy score present",
            )
        )
    if event_payload.get("metadata", {}).get("archive_scan"):
        findings.append(
            DetectionFinding(
                detector="archive",
                severity="low",
                detail="archive scan metadata provided",
            )
        )
    return findings
