import re
from dataclasses import dataclass
from typing import Iterable

from server.models.models import PolicyRule


@dataclass
class Decision:
    decision: str
    rule_id: int | None
    severity: str
    reason: str
    score: int = 0


class PolicyEngine:
    def __init__(self, rules: Iterable[PolicyRule]):
        self.rules = sorted(rules, key=lambda r: r.priority)

    def evaluate(self, event: dict) -> Decision:
        for rule in self.rules:
            if rule.is_whitelist and self._match_rule(rule, event):
                return Decision("allow", rule.id, "low", "Matched whitelist rule", 0)
            if not self._match_rule(rule, event):
                continue
            reason = f"Matched rule {rule.rule_type}"
            severity = rule.severity
            score = rule.severity_score or 0
            return Decision(rule.action, rule.id, severity, reason, score)
        return Decision("allow", None, "low", "No rules matched", 0)

    def _match_rule(self, rule: PolicyRule, event: dict) -> bool:
        if rule.usb_only and not event.get("metadata", {}).get("usb_copy"):
            return False
        content = event.get("metadata", {}).get("content", "")
        file_path = event.get("file_path") or ""
        if rule.rule_type in {"keyword", "keywords"}:
            keywords = []
            if rule.pattern:
                keywords.append(rule.pattern)
            if rule.keywords:
                keywords.extend(rule.keywords)
            return any(keyword.lower() in content.lower() for keyword in keywords if keyword)
        if rule.rule_type == "regex" and rule.pattern:
            return re.search(rule.pattern, content or "") is not None
        if rule.rule_type == "hash" and rule.hashes:
            file_hash = (event.get("file_hash") or "").lower()
            return file_hash in [value.lower() for value in rule.hashes]
        if rule.rule_type == "extension" and rule.file_extension:
            return file_path.lower().endswith(rule.file_extension.lower())
        if rule.rule_type == "size":
            file_size = event.get("file_size") or 0
            if rule.min_size and file_size < rule.min_size:
                return False
            if rule.max_size and file_size > rule.max_size:
                return False
            return True
        return False
