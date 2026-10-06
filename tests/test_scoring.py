from causalfence.loader import load_graph
from causalfence.engine import run_all_checks, Result, Finding
from causalfence.scoring import compute_score


def score_of(path):
    return compute_score(run_all_checks(load_graph(path)))


def test_safe_scores_100():
    s = score_of("graphs/safe.yml")
    assert s.value == 100
    assert s.label == "SAFE"


def test_extra_path_still_safe():
    assert score_of("graphs/extra_path.yml").value == 100


def test_bypass_scores_70():
    s = score_of("graphs/bypass.yml")
    assert s.value == 70
    assert s.label == "LOW RISK"


def test_public_db_scores_60():
    s = score_of("graphs/public_db.yml")
    assert s.value == 60
    assert s.label == "MEDIUM RISK"


def test_score_never_below_zero():
    big = [Finding("X", [], "", "HIGH", 60, "") for _ in range(3)]
    s = compute_score(Result(passed=False, findings=big))
    assert s.value == 0
    assert s.label == "HIGH RISK"