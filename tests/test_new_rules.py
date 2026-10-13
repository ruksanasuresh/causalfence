"""Step 4b: LAMBDA_URL_OPEN, OVERBROAD_IAM and PUBLIC_S3_BUCKET."""
from pathlib import Path
import yaml
from causalfence.engine import run_all_checks
from causalfence.iac_parser import parse_template
from causalfence.loader import load_graph
from causalfence.risk import assess
ROOT = Path(__file__).resolve().parent.parent
RISKY = ROOT / "infra" / "examples" / "risky.yaml"
TABLE = """
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      Tags: [{Key: sensitivity, Value: phi}]
"""
def _run(tmp_path, body, source="t.yaml"):
    tpl = tmp_path / source
    tpl.write_text("Transform: AWS::Serverless-2016-10-31\nResources:\n" + body,
                   encoding="utf-8")
    data = parse_template(str(tpl))
    data.pop("warnings")
    data["source_file"] = source
    g = tmp_path / "g.yml"
    g.write_text(yaml.safe_dump(data), encoding="utf-8")
    G = load_graph(str(g))
    return G, run_all_checks(G)
def _fn(extra):
    return f"""
  Fn:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.handler
      Runtime: python3.13
{extra}"""
GOOD_POLICY = """      Policies:
        - DynamoDBCrudPolicy: {TableName: !Ref Table}
"""
WILD_POLICY = """      Policies:
        - Statement:
            - {Effect: Allow, Action: "dynamodb:*", Resource: !GetAtt Table.Arn}
"""
URL_NONE = "      FunctionUrlConfig: {AuthType: NONE}\n"
URL_IAM = "      FunctionUrlConfig: {AuthType: AWS_IAM}\n"
# ---------------------------------------------------------- Lambda URL --
def test_open_function_url_reaching_phi_is_flagged(tmp_path):
    _, r = _run(tmp_path, TABLE + _fn(URL_NONE + GOOD_POLICY))
    assert [f.rule for f in r.findings] == ["LAMBDA_URL_OPEN"]
    assert r.findings[0].path == ["FnUrl", "Fn", "Table"]
def test_open_url_is_not_double_reported_as_auth_bypass(tmp_path):
    _, r = _run(tmp_path, TABLE + _fn(URL_NONE + GOOD_POLICY))
    assert "AUTH_BYPASS" not in {f.rule for f in r.findings}
def test_iam_protected_function_url_is_fine(tmp_path):
    _, r = _run(tmp_path, TABLE + _fn(URL_IAM + GOOD_POLICY))
    assert r.passed
def test_standalone_lambda_url_resource(tmp_path):
    body = TABLE + _fn(GOOD_POLICY) + """
  FnUrlRes:
    Type: AWS::Lambda::Url
    Properties: {AuthType: NONE, TargetFunctionArn: !GetAtt Fn.Arn}
"""
    _, r = _run(tmp_path, body)
    assert [f.rule for f in r.findings] == ["LAMBDA_URL_OPEN"]
def test_open_url_with_no_sensitive_data_is_not_flagged(tmp_path):
    _, r = _run(tmp_path, _fn(URL_NONE))
    assert r.passed
# -------------------------------------------------------- over-broad IAM --
def test_wildcard_policy_behind_public_entry_is_flagged(tmp_path):
    _, r = _run(tmp_path, TABLE + _fn(URL_IAM + WILD_POLICY))
    assert [f.rule for f in r.findings] == ["OVERBROAD_IAM"]
    assert "dynamodb:*" in r.findings[0].evidence[-1]
def test_scoped_policy_is_not_flagged(tmp_path):
    _, r = _run(tmp_path, TABLE + _fn(URL_IAM + GOOD_POLICY))
    assert r.passed
def test_wildcard_policy_not_reachable_from_public_is_ignored(tmp_path):
    _, r = _run(tmp_path, TABLE + _fn(WILD_POLICY))
    assert r.passed
# ------------------------------------------------------------ public S3 --
BUCKET_POLICY = """
  Policy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Bucket
      PolicyDocument:
        Statement:
          - {Effect: Allow, Principal: "*", Action: "s3:GetObject", Resource: "*"}
"""
BLOCK = """      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
"""
def test_bucket_policy_for_everyone_is_flagged(tmp_path):
    body = "\n  Bucket:\n    Type: AWS::S3::Bucket\n" + BUCKET_POLICY
    G, r = _run(tmp_path, body)
    assert [f.rule for f in r.findings] == ["PUBLIC_S3_BUCKET"]
    assert "line" in r.findings[0].evidence[0]
def test_block_public_access_makes_it_safe(tmp_path):
    body = ("\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
            + BLOCK + BUCKET_POLICY)
    _, r = _run(tmp_path, body)
    assert r.passed
def test_public_read_acl_is_flagged(tmp_path):
    body = ("\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
            "      AccessControl: PublicRead\n")
    _, r = _run(tmp_path, body)
    assert [f.rule for f in r.findings] == ["PUBLIC_S3_BUCKET"]
def test_private_bucket_is_fine(tmp_path):
    _, r = _run(tmp_path, "\n  Bucket:\n    Type: AWS::S3::Bucket\n")
    assert r.passed
def test_phi_bucket_is_high_untagged_is_medium(tmp_path):
    tagged = ("\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n"
              "      Tags: [{Key: sensitivity, Value: phi}]\n" + BUCKET_POLICY)
    plain = "\n  Bucket:\n    Type: AWS::S3::Bucket\n" + BUCKET_POLICY
    G1, r1 = _run(tmp_path, tagged)
    assert assess(G1, r1).label == "HIGH"
    G2, r2 = _run(tmp_path, plain)
    assert assess(G2, r2).label == "MEDIUM"
# ----------------------------------------------------------- demo file --
def test_risky_demo_template_triggers_all_three_rules(tmp_path):
    data = parse_template(str(RISKY))
    data.pop("warnings")
    g = tmp_path / "g.yml"
    g.write_text(yaml.safe_dump(data), encoding="utf-8")
    r = run_all_checks(load_graph(str(g)))
    assert {f.rule for f in r.findings} == {
        "LAMBDA_URL_OPEN", "OVERBROAD_IAM", "PUBLIC_S3_BUCKET"}
def test_hospital_template_results_unchanged():
    tpl = ROOT / "infra" / "template.yaml"
    if not tpl.exists():
        return
    for mode, expected in (("safe", set()), ("broken", {"AUTH_BYPASS"})):
        data = parse_template(str(tpl), {"AuthMode": mode})
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "g.yml")
            data.pop("warnings")
            Path(p).write_text(yaml.safe_dump(data), encoding="utf-8")
            rules = {f.rule for f in run_all_checks(load_graph(p)).findings}
        assert rules == expected
