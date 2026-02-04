import re
from dataclasses import dataclass
from typing import Iterable

from app.db.models import PolicyRule


@dataclass
class Decision:
    decision: str
    rule_id: int | None
    severity: str
    reason: str


class PolicyEngine:
    def __init__(self, rules: Iterable[PolicyRule]):
        self.rules = sorted(rules, key=lambda r: r.priority)

    def evaluate(self, event: dict) -> Decision:
        for rule in self.rules:
            if not self._match_rule(rule, event):
                continue
            reason = f"Matched rule {rule.rule_type}"
            return Decision(rule.action, rule.id, rule.severity, reason)
        return Decision("allow", None, "low", "No rules matched")

    def _match_rule(self, rule: PolicyRule, event: dict) -> bool:
        if rule.usb_only and not event.get("metadata", {}).get("usb_copy"):
            return False
        if rule.rule_type == "keyword" and rule.pattern:
            content = event.get("metadata", {}).get("content", "")
            return rule.pattern.lower() in content.lower()
        if rule.rule_type == "regex" and rule.pattern:
            content = event.get("metadata", {}).get("content", "")
            return re.search(rule.pattern, content or "") is not None
        if rule.rule_type == "extension" and rule.file_extension:
            file_path = event.get("file_path") or ""
            return file_path.lower().endswith(rule.file_extension.lower())
        if rule.rule_type == "size":
            file_size = event.get("file_size") or 0
            if rule.min_size and file_size < rule.min_size:
                return False
            if rule.max_size and file_size > rule.max_size:
                return False
            return True
        return False
