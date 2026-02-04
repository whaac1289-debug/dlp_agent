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
            yield rule
