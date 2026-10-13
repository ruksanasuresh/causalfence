"""The live scanner against simulated AWS responses (no account needed)."""
import boto3
import pytest
import yaml
from botocore.exceptions import ClientError
from causalfence import scanner
from causalfence.engine import run_all_checks
from causalfence.loader import load_graph
ACCOUNT = "arn:aws:dynamodb:ap-south-1:111122223333"
def err(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")
class FakeAws:
    """One fake 'stack'. Build it up, then hand it to scan_stack via monkeypatch."""
    def __init__(self):
        self.resources, self.apis, self.functions = [], {}, {}
        self.tables, self.buckets = {}, {}
    # -- builders ------------------------------------------------------
    def add(self, rtype, logical, physical):
        self.resources.append({"ResourceType": rtype, "LogicalResourceId": logical,
                               "PhysicalResourceId": physical})
    def table(self, logical="PatientsTable", sensitivity="phi"):
        self.add("AWS::DynamoDB::Table", logical, logical + "-phys")
        self.tables[logical + "-phys"] = {"sensitivity": sensitivity}
    def function(self, logical, url=None, url_error=None, policy=None, table="PatientsTable"):
        phys = logical + "-fn"
        self.add("AWS::Lambda::Function", logical, phys)
        self.functions[phys] = {
            "url": url, "url_error": url_error,
            "policy": policy if policy is not None else [
                {"Effect": "Allow",
                 "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
                 "Resource": f"{ACCOUNT}:table/{table}-phys"}]}
        return phys
    def api(self, routes, authorizer_fn=None):
        self.add("AWS::ApiGatewayV2::Api", "HospitalApi", "api1")
        self.apis["api1"] = {"routes": routes, "authorizer_fn": authorizer_fn}
    def bucket(self, logical="ReportsBucket", tags=None, block=None, policy_public=False, acl_public=False):
        self.add("AWS::S3::Bucket", logical, logical + "-phys")
        self.buckets[logical + "-phys"] = dict(tags=tags, block=block,
                                               policy_public=policy_public, acl_public=acl_public)
    # -- fake boto3 clients --------------------------------------------
    def client(self, name):
        return getattr(self, "_" + name.replace("apigatewayv2", "apigw"))()
    def _cloudformation(self):
        me = self
        return type("C", (), {"describe_stack_resources":
                    lambda s, StackName: {"StackResources": me.resources}})()
    def _dynamodb(self):
        me = self
        return type("D", (), {
            "describe_table": lambda s, TableName: {"Table": {"TableArn": "arn:" + TableName}},
            "list_tags_of_resource": lambda s, ResourceArn: {"Tags": [
                {"Key": "sensitivity", "Value": me.tables[ResourceArn[4:]]["sensitivity"]}]},
        })()
    def _apigw(self):
        me = self
        def routes(s, ApiId):
            return {"Items": [{"RouteKey": r["key"], "RouteId": r["id"],
                               "AuthorizationType": r.get("auth", "NONE"),
                               "AuthorizerId": "az1", "Target": "integrations/i1"}
                              for r in me.apis[ApiId]["routes"]]}
        def authorizers(s, ApiId):
            fn = me.apis[ApiId]["authorizer_fn"]
            if not fn:
                return {"Items": []}
            return {"Items": [{"AuthorizerId": "az1",
                               "AuthorizerUri": f"arn:aws:lambda:r:1:function:{fn}/invocations"}]}
        def integrations(s, ApiId):
            target = [p for p in me.functions if "Patient" in p][0]
            return {"Items": [{"IntegrationId": "i1",
                               "IntegrationUri": f"arn:aws:lambda:r:1:function:{target}"}]}
        return type("A", (), {"get_api": lambda s, ApiId: {"Name": "hospital-api"},
                              "get_routes": routes, "get_authorizers": authorizers,
                              "get_integrations": integrations})()
    def _lambda(self):
        me = self
        def url(s, FunctionName):
            f = me.functions[FunctionName]
            if f["url_error"]:
                raise err(f["url_error"])
            if not f["url"]:
                raise err("ResourceNotFoundException")
            return {"AuthType": f["url"], "FunctionUrl": "https://x.lambda-url"}
        return type("L", (), {
            "get_function_url_config": lambda s, FunctionName: url(s, FunctionName),
            "get_function_configuration": lambda s, FunctionName: {
                "Role": "arn:aws:iam::1:role/role-" + FunctionName}})()
    def _iam(self):
        me = self
        return type("I", (), {
            "list_role_policies": lambda s, RoleName: {"PolicyNames": ["inline"]},
            "get_role_policy": lambda s, RoleName, PolicyName: {"PolicyDocument": {
                "Statement": me.functions[RoleName[5:]]["policy"]}},
            "list_attached_role_policies": lambda s, RoleName: {"AttachedPolicies": []},
        })()
    def _s3(self):
        me = self
        def tagging(s, Bucket):
            if not me.buckets[Bucket]["tags"]:
                raise err("NoSuchTagSet")
            return {"TagSet": [{"Key": k, "Value": v} for k, v in me.buckets[Bucket]["tags"].items()]}
        def block(s, Bucket):
            b = me.buckets[Bucket]["block"]
            if b is None:
                raise err("NoSuchPublicAccessBlockConfiguration")
            return {"PublicAccessBlockConfiguration": b}
        def status(s, Bucket):
            if not me.buckets[Bucket]["policy_public"]:
                raise err("NoSuchBucketPolicy")
            return {"PolicyStatus": {"IsPublic": True}}
        def acl(s, Bucket):
            grants = []
            if me.buckets[Bucket]["acl_public"]:
                grants.append({"Grantee": {"URI": scanner.ALL_USERS}, "Permission": "READ"})
            return {"Grants": grants}
        return type("S", (), {"get_bucket_tagging": tagging, "get_public_access_block": block,
                              "get_bucket_policy_status": status, "get_bucket_acl": acl})()
def scan(monkeypatch, tmp_path, fake):
    monkeypatch.setattr(boto3.session, "Session",
                        lambda region_name=None: type("S", (), {"client": lambda s, n: fake.client(n)})())
    graph = scanner.scan_stack("stack", "ap-south-1")
    p = tmp_path / "live.yml"
    p.write_text(yaml.safe_dump(graph), encoding="utf-8")
    G = load_graph(str(p))
    return graph, G, run_all_checks(G)
def rules(result):
    return [f.rule for f in result.findings]
# -------------------------------------------- the original hospital apps --
def test_route_without_authorizer_is_auth_bypass(monkeypatch, tmp_path):
    fake = FakeAws(); fake.table(); fake.function("PatientLambda")
    fake.add("AWS::ApiGatewayV2::Route", "PatientsRoute", "r1")
    fake.api([{"key": "ANY /patients", "id": "r1"}])
    graph, G, result = scan(monkeypatch, tmp_path, fake)
    assert rules(result) == ["AUTH_BYPASS"]
    first = next(e for e in graph["edges"] if e["label"] == "ANY /patients")
    assert first["resource"] == "PatientsRoute"
    assert "(resource PatientsRoute)" in result.findings[0].evidence[0]
def test_route_with_custom_authorizer_is_safe(monkeypatch, tmp_path):
    fake = FakeAws(); fake.table(); fake.function("PatientLambda"); fake.function("AuthLambda")
    fake.api([{"key": "ANY /patients", "id": "r1", "auth": "CUSTOM"}], authorizer_fn="AuthLambda-fn")
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed
# ---------------------------------------------------------- Function URL --
def test_open_function_url_is_flagged(monkeypatch, tmp_path):
    fake = FakeAws(); fake.table(); fake.function("ReportLambda", url="NONE")
    graph, G, result = scan(monkeypatch, tmp_path, fake)
    assert rules(result) == ["LAMBDA_URL_OPEN"]
    assert result.findings[0].path == ["ReportLambdaUrl", "ReportLambda", "PatientsTable"]
    assert "live AWS scan" in result.findings[0].evidence[0]
def test_iam_protected_function_url_is_not_flagged(monkeypatch, tmp_path):
    fake = FakeAws(); fake.table(); fake.function("ReportLambda", url="AWS_IAM")
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed
def test_function_without_url_is_fine(monkeypatch, tmp_path):
    fake = FakeAws(); fake.table(); fake.function("ReportLambda")
    graph, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed and not any(n["kind"] == "lambda-url" for n in graph["nodes"])
def test_access_denied_on_url_config_only_warns(monkeypatch, tmp_path, capsys):
    fake = FakeAws(); fake.table(); fake.function("ReportLambda", url_error="AccessDeniedException")
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed
    assert "cannot read the Function URL" in capsys.readouterr().err
# ------------------------------------------------------------ wildcard IAM --
def test_wildcard_role_behind_protected_url_is_flagged(monkeypatch, tmp_path):
    star = [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": f"{ACCOUNT}:table/PatientsTable-phys"}]
    fake = FakeAws(); fake.table(); fake.function("ReportLambda", url="AWS_IAM", policy=star)
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert rules(result) == ["OVERBROAD_IAM"]
def test_star_resource_with_specific_actions_is_flagged(monkeypatch, tmp_path):
    pol = [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": "*"}]
    fake = FakeAws(); fake.table(); fake.function("ReportLambda", url="AWS_IAM", policy=pol)
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert rules(result) == ["OVERBROAD_IAM"]
def test_scoped_role_is_not_flagged(monkeypatch, tmp_path):
    fake = FakeAws(); fake.table(); fake.function("ReportLambda", url="AWS_IAM")
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed
# --------------------------------------------------------------- public S3 --
def test_public_bucket_policy_is_flagged(monkeypatch, tmp_path):
    fake = FakeAws(); fake.bucket(tags={"sensitivity": "phi"}, policy_public=True)
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert rules(result) == ["PUBLIC_S3_BUCKET"]
    assert "live AWS scan" in result.findings[0].evidence[0]
def test_fully_blocked_bucket_is_safe_even_with_public_policy(monkeypatch, tmp_path):
    block = {k: True for k in ("BlockPublicAcls", "BlockPublicPolicy",
                               "IgnorePublicAcls", "RestrictPublicBuckets")}
    fake = FakeAws(); fake.bucket(policy_public=True, block=block)
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed
def test_public_acl_is_flagged_and_missing_tags_are_ok(monkeypatch, tmp_path):
    fake = FakeAws(); fake.bucket(acl_public=True)
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert rules(result) == ["PUBLIC_S3_BUCKET"]
def test_private_bucket_is_fine(monkeypatch, tmp_path):
    fake = FakeAws(); fake.bucket()
    _, _, result = scan(monkeypatch, tmp_path, fake)
    assert result.passed
