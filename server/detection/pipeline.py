import math
import re
from dataclasses import dataclass

from server.models import models


@dataclass
class DetectionFinding:
    detector: str
    score: int
    detail: str
    tags: list[str]


@dataclass
class DetectionReport:
    findings: list[DetectionFinding]
    score: int
    severity: str


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def _severity_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def run_detection(event_payload: dict, rules: list[models.PolicyRule]) -> DetectionReport:
    findings: list[DetectionFinding] = []
    metadata = event_payload.get("metadata") or {}
    content = metadata.get("content", "")
    file_hash = (event_payload.get("file_hash") or "").lower()
    file_path = event_payload.get("file_path") or ""

    entropy_score = _entropy(content)
    if entropy_score >= 4.0:
        findings.append(
            DetectionFinding(
                detector="entropy",
                score=15,
                detail=f"entropy={entropy_score:.2f}",
                tags=["entropy"],
            )
        )

    if file_path:
        extension = file_path.split(".")[-1].lower() if "." in file_path else ""
        if extension in {"exe", "dll", "zip", "7z", "rar"}:
            findings.append(
                DetectionFinding(
                    detector="file_type",
                    score=10,
                    detail=f"extension={extension}",
                    tags=["file_type"],
                )
            )

    for rule in rules:
        tags = rule.tags or []
        if rule.rule_type == "regex" and rule.pattern:
            if re.search(rule.pattern, content or ""):
                findings.append(
                    DetectionFinding(
                        detector="regex",
                        score=rule.severity_score or 20,
                        detail=f"regex={rule.pattern}",
                        tags=tags,
                    )
                )
        if rule.rule_type in {"keyword", "keywords"}:
            keywords = []
            if rule.pattern:
                keywords.append(rule.pattern)
            if rule.keywords:
                keywords.extend(rule.keywords)
            for keyword in keywords:
                if keyword and keyword.lower() in (content or "").lower():
                    findings.append(
                        DetectionFinding(
                            detector="keyword",
                            score=rule.severity_score or 15,
                            detail=f"keyword={keyword}",
                            tags=tags,
                        )
                    )
                    break
        if rule.rule_type == "hash" and rule.hashes:
            if file_hash in [value.lower() for value in rule.hashes]:
                findings.append(
                    DetectionFinding(
                        detector="hash",
                        score=rule.severity_score or 30,
                        detail="hash match",
                        tags=tags,
                    )
                )

    total_score = sum(finding.score for finding in findings)
    severity = _severity_for_score(total_score)
    return DetectionReport(findings=findings, score=total_score, severity=severity)
