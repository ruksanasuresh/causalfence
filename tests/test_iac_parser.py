from pathlib import Path

import pytest
import yaml

from causalfence.engine import run_all_checks
from causalfence.iac_parser import parse_template
from causalfence.loader import load_graph

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "infra" / "template.yaml"


def _graph(tmp_path, data):
    p = tmp_path / "g.yml"
    p.write_text(yaml.safe_dump({k: data[k] for k in ("nodes", "edges")}), encoding="utf-8")
    return load_graph(str(p))


def _shape(data):
    return ({n["id"] for n in data["nodes"]},
            {(e["from"], e["to"]) for e in data["edges"]})


def test_safe_template_passes(tmp_path):
    data = parse_template(TEMPLATE, {"AuthMode": "safe"})
    assert run_all_checks(_graph(tmp_path, data)).passed


def test_broken_template_fails_with_auth_bypass(tmp_path):
    data = parse_template(TEMPLATE, {"AuthMode": "broken"})
    result = run_all_checks(_graph(tmp_path, data))
    assert not result.passed
    assert result.findings[0].rule == "AUTH_BYPASS"
    assert result.findings[0].path == ["HospitalApi", "PatientLambda", "PatientsTable"]


def test_conditional_resources_are_dropped_in_broken_mode():
    safe = {n["id"] for n in parse_template(TEMPLATE, {"AuthMode": "safe"})["nodes"]}
    broken = {n["id"] for n in parse_template(TEMPLATE, {"AuthMode": "broken"})["nodes"]}
    assert "AuthLambda" in safe and "AuthLambda" not in broken


def test_default_parameter_is_safe():
    assert _shape(parse_template(TEMPLATE)) == _shape(parse_template(TEMPLATE, {"AuthMode": "safe"}))


def test_nodes_carry_template_line_numbers():
    data = parse_template(TEMPLATE)
    table = next(n for n in data["nodes"] if n["id"] == "PatientsTable")
    assert table["source"] == "template" and table["line"] > 0
    assert table["sensitivity"] == "phi"


@pytest.mark.parametrize("mode", ["safe", "broken"])
def test_parser_matches_live_scan(mode):
    """The template graph must have the same shape as the Boto3 scan of the deployed stack."""
    live = ROOT / "graphs" / f"live-causalfence-{mode}.yml"
    if not live.exists():
        pytest.skip(f"{live.name} not present")
    scanned = yaml.safe_load(live.read_text(encoding="utf-8"))
    assert _shape(parse_template(TEMPLATE, {"AuthMode": mode})) == _shape(scanned)


def test_unknown_parameter_is_rejected():
    with pytest.raises(ValueError):
        parse_template(TEMPLATE, {"Nope": "x"})


MINI = """
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      Tags: [{Key: sensitivity, Value: phi}]
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Policies:
        - Statement:
            - Effect: Allow
              Action: "dynamodb:*"
              Resource: "*"
  Api:
    Type: AWS::ApiGatewayV2::Api
  Integ:
    Type: AWS::ApiGatewayV2::Integration
    Properties:
      ApiId: !Ref Api
      IntegrationUri: !GetAtt Fn.Arn
  Route:
    Type: AWS::ApiGatewayV2::Route
    Properties:
      ApiId: !Ref Api
      RouteKey: "GET /x"
      Target: !Sub "integrations/${Integ}"
      AuthorizationType: %s
"""


def _mini(tmp_path, auth_type):
    p = tmp_path / "t.yaml"
    p.write_text(MINI % auth_type, encoding="utf-8")
    return parse_template(p)


def test_inline_policy_with_wildcard_resource_links_function_to_table(tmp_path):
    data = _mini(tmp_path, "NONE")
    assert ("Fn", "Table") in _shape(data)[1]


def test_jwt_route_gets_a_virtual_auth_node(tmp_path):
    data = _mini(tmp_path, "JWT")
    ids, edges = _shape(data)
    assert "jwt-auth" in ids and ("Api", "jwt-auth") in edges and ("jwt-auth", "Fn") in edges
    rules = {f.rule for f in run_all_checks(_graph(tmp_path, data)).findings}
    # the auth rules are satisfied; the sample's dynamodb:* is a separate rule
    assert not rules & {"AUTH_BYPASS", "PUBLIC_DB_EXPOSURE"}
def test_open_route_is_flagged(tmp_path):
    data = _mini(tmp_path, "NONE")
    assert not run_all_checks(_graph(tmp_path, data)).passed


def test_custom_without_authorizer_is_treated_as_open(tmp_path):
    data = _mini(tmp_path, "CUSTOM")
    assert any("no authorizer" in w for w in data["warnings"])
    assert not run_all_checks(_graph(tmp_path, data)).passed