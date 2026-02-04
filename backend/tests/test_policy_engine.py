from app.services.policy_engine import PolicyEngine
from app.db.models import PolicyRule


def test_policy_engine_matches_keyword():
    rule = PolicyRule(id=1, rule_type="keyword", pattern="secret", action="alert", severity="high", priority=1)
    engine = PolicyEngine([rule])
    decision = engine.evaluate({"metadata": {"content": "this is secret"}})
    assert decision.decision == "alert"
    assert decision.rule_id == 1
