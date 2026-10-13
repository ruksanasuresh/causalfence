"""Step 3: findings carry evidence (file + line) and a copy-paste fix."""
from pathlib import Path

import yaml

from causalfence.engine import run_all_checks
from causalfence.iac_parser import parse_template
from causalfence.loader import load_graph
from causalfence.report import format_report

TEMPLATE = str(Path(__file__).resolve().parent.parent / "infra" / "template.yaml")


def _graph_file(tmp_path, params, source_file="infra/template.yaml"):
    data = parse_template(TEMPLATE, params)
    data.pop("warnings")
    data["source_file"] = source_file
    p = tmp_path / "g.yml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


def test_loader_keeps_edge_details(tmp_path):
    G = load_graph(_graph_file(tmp_path, {"AuthMode": "broken"}))
    e = G.edges["HospitalApi", "PatientLambda"]
    assert e["label"] == "ANY /patients"
    assert e["resource"] == "PatientsRoute"
    assert isinstance(e["line"], int)
    assert G.graph["source_file"] == "infra/template.yaml"


def test_auth_bypass_has_evidence_with_line(tmp_path):
    G = load_graph(_graph_file(tmp_path, {"AuthMode": "broken"}))
    f = run_all_checks(G).findings[0]
    assert f.rule == "AUTH_BYPASS"
    first = f.evidence[0]
    assert "ANY /patients" in first and "PatientsRoute" in first
    assert "infra/template.yaml, line" in first
    assert len(f.evidence) == len(f.path) - 1


def test_fix_snippet_names_the_route(tmp_path):
    G = load_graph(_graph_file(tmp_path, {"AuthMode": "broken"}))
    f = run_all_checks(G).findings[0]
    assert "AuthorizationType: CUSTOM" in f.fix_snippet
    assert "PatientsRoute" in f.fix_snippet
    assert "{" not in f.fix_snippet


def test_live_graph_evidence_says_live_aws(tmp_path):
    p = tmp_path / "live.yml"
    p.write_text(yaml.safe_dump({
        "nodes": [{"id": "api", "trust": "public"}, {"id": "fn"},
                  {"id": "db", "sensitivity": "phi"}],
        "edges": [{"from": "api", "to": "fn", "label": "ANY /patients"},
                  {"from": "fn", "to": "db", "label": "dynamodb"}]}), encoding="utf-8")
    f = run_all_checks(load_graph(str(p))).findings[0]
    assert all("live AWS scan" in line for line in f.evidence)
    assert "<your route>" in f.fix_snippet


def test_safe_template_has_no_findings(tmp_path):
    G = load_graph(_graph_file(tmp_path, {"AuthMode": "safe"}))
    assert run_all_checks(G).passed


def test_report_text_contains_all_parts(tmp_path):
    G = load_graph(_graph_file(tmp_path, {"AuthMode": "broken"}))
    text = format_report(run_all_checks(G))
    for word in ("AUTH_BYPASS", "Path:", "Evidence:", "Copy-paste fix:", "line"):
        assert word in text