from causalfence.loader import load_graph
from causalfence.engine import run_all_checks, load_rules


def test_rules_file_has_penalties():
    rules = load_rules()
    assert rules["AUTH_BYPASS"]["penalty"] == 30
    assert rules["PUBLIC_DB_EXPOSURE"]["penalty"] == 40


def test_public_db_exposure_detected():
    result = run_all_checks(load_graph("graphs/public_db.yml"))
    assert not result.passed
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule == "PUBLIC_DB_EXPOSURE"
    assert f.severity == "CRITICAL"
    assert f.path == ["public-api", "phi-table"]


def test_bypass_finding_has_severity_and_fix():
    result = run_all_checks(load_graph("graphs/bypass.yml"))
    f = result.findings[0]
    assert f.rule == "AUTH_BYPASS"
    assert f.severity == "HIGH"
    assert f.penalty == 30
    assert "authorizer" in f.remediation
    assert result.total_penalty == 30