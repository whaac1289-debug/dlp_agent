from server.detection.pipeline import run_detection
from server.models.models import PolicyRule


def test_detection_regex_match():
    rule = PolicyRule(rule_type="regex", pattern="secret", severity_score=20, action="alert")
    report = run_detection({"metadata": {"content": "secret data"}}, [rule])
    assert any(finding.detector == "regex" for finding in report.findings)


def test_detection_keyword_match():
    rule = PolicyRule(rule_type="keywords", keywords=["confidential"], severity_score=15, action="alert")
    report = run_detection({"metadata": {"content": "confidential data"}}, [rule])
    assert any(finding.detector == "keyword" for finding in report.findings)


def test_detection_entropy_threshold():
    high_entropy = "aB3!xZ9" * 10
    report = run_detection({"metadata": {"content": high_entropy}}, [])
    assert any(finding.detector == "entropy" for finding in report.findings)
