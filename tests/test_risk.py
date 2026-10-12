"""Step 4a: explainable verdict (SAFE / MEDIUM / HIGH) with reasons."""
import networkx as nx

from causalfence.engine import run_all_checks
from causalfence.risk import assess


def _graph(sensitivity="phi", auth_type=None, confidence=None, direct=False):
    G = nx.DiGraph()
    pub = {"trust": "public"}
    if auth_type:
        pub["auth_type"] = auth_type
    G.add_node("api", **pub)
    G.add_node("fn")
    G.add_node("db", sensitivity=sensitivity)
    attrs = {"confidence": confidence} if confidence else {}
    if direct:
        G.add_edge("api", "db", label="direct", **attrs)
    else:
        G.add_edge("api", "fn", label="ANY /x", **attrs)
        G.add_edge("fn", "db", label="crud", **attrs)
    return G


def test_no_findings_is_safe():
    G = _graph()
    G.remove_edge("api", "fn")
    v = assess(G, run_all_checks(G))
    assert v.label == "SAFE" and not v.failed


def test_phi_without_auth_is_high():
    G = _graph("phi")
    v = assess(G, run_all_checks(G))
    assert v.label == "HIGH" and v.rule_ids == ["AUTH_BYPASS"]
    assert "Triggered by: AUTH_BYPASS" in v.headline()


def test_failed_check_is_never_safe_or_low():
    G = _graph("internal", confidence="low")
    v = assess(G, run_all_checks(G))
    assert v.failed and v.label == "MEDIUM"


def test_direct_db_exposure_is_high():
    G = _graph("phi", direct=True)
    v = assess(G, run_all_checks(G))
    assert v.label == "HIGH" and "PUBLIC_DB_EXPOSURE" in v.rule_ids


def test_more_sensitive_data_raises_the_label():
    medium = assess(_graph("internal"), run_all_checks(_graph("internal")))
    high = assess(_graph("phi"), run_all_checks(_graph("phi")))
    assert (medium.label, high.label) == ("MEDIUM", "HIGH")


def test_low_confidence_can_lower_the_label():
    G = _graph("pii", confidence="low")
    assert assess(G, run_all_checks(G)).label == "MEDIUM"


def test_explanation_names_all_four_factors():
    G = _graph("phi")
    text = assess(G, run_all_checks(G)).items[0].explain()
    for word in ("severity", "data PHI", "exposure", "confidence"):
        assert word in text


def test_headline_has_no_bare_number():
    G = _graph("phi")
    assert "/100" not in assess(G, run_all_checks(G)).headline()