from server.models.models import PolicyRule
from server.policy.engine import PolicyEngine


def test_policy_engine_matches_keyword():
    rule = PolicyRule(
        id=1,
        rule_type="keyword",
        pattern="secret",
        action="alert",
        severity="high",
        priority=1,
        keywords=["secret"],
    )
    engine = PolicyEngine([rule])
    decision = engine.evaluate({"metadata": {"content": "this is secret"}})
    assert decision.decision == "alert"
    assert decision.rule_id == 1


def test_policy_engine_whitelist():
    rule = PolicyRule(
        id=2,
        rule_type="keyword",
        pattern="trusted",
        action="alert",
        severity="high",
        priority=1,
        is_whitelist=True,
    )
    engine = PolicyEngine([rule])
    decision = engine.evaluate({"metadata": {"content": "trusted content"}})
    assert decision.decision == "allow"
