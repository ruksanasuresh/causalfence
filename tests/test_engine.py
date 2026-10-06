from causalfence.loader import load_graph
from causalfence.engine import run_all_checks


def test_safe_architecture_passes():
    result = run_all_checks(load_graph("graphs/safe.yml"))
    assert result.passed
    assert result.findings == []


def test_auth_bypass_fails():
    result = run_all_checks(load_graph("graphs/bypass.yml"))
    assert not result.passed
    assert len(result.findings) == 1
    assert result.findings[0].rule == "AUTH_BYPASS"
    assert result.findings[0].path == [
        "public-api", "patient-lambda", "phi-table"
    ]


def test_extra_valid_path_passes():
    result = run_all_checks(load_graph("graphs/extra_path.yml"))
    assert result.passed