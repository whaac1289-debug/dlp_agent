import json
from pathlib import Path
from typing import Iterable


DEFAULT_RULE_PATHS = (
    "rules/pii_rules.json",
    "rules/secret_rules.json",
    "rules/compliance_rules.json",
    "rules/default_policy.json",
)


def load_rule_sets(base_dir: str | Path = ".") -> list[dict]:
    rule_sets: list[dict] = []
    for rel_path in DEFAULT_RULE_PATHS:
        path = Path(base_dir) / rel_path
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        rule_sets.append(payload)
    return rule_sets


def iter_rules(rule_sets: Iterable[dict]) -> Iterable[dict]:
    for payload in rule_sets:
        for rule in payload.get("rules", []):
            rule_type = rule.get("type") or rule.get("rule_type")
            action = "allow" if rule_type == "allow" else rule.get("action", "alert")
            severity_score = int(rule.get("severity", 0))
            severity = "low"
            if severity_score >= 8:
                severity = "high"
            elif severity_score >= 5:
                severity = "medium"
            normalized = {
                "rule_type": rule_type,
                "pattern": rule.get("pattern"),
                "keywords": rule.get("keywords"),
                "hashes": rule.get("hashes"),
                "file_extension": rule.get("file_extension"),
                "min_size": rule.get("min_size"),
                "max_size": rule.get("max_size"),
                "usb_only": rule.get("usb_only", False),
                "action": action,
                "severity": rule.get("severity_label", severity),
                "severity_score": severity_score,
                "tags": rule.get("tags"),
                "is_whitelist": rule.get("whitelist", False),
                "priority": rule.get("priority", 100),
            }
            yield normalized
