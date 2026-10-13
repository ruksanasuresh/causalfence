"""Live AWS scanner: rebuilds the architecture graph of a deployed
CloudFormation stack with Boto3 and writes it in the graph.yml format."""
import argparse
import sys
from pathlib import Path
import boto3
import yaml
from botocore.exceptions import ClientError
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
def _as_list(x):
    return x if isinstance(x, list) else [x]
def _lambda_name(uri: str) -> str:
    """Extract the function name from a Lambda ARN or an API Gateway invoke URI."""
    return uri.split(":function:")[1].split(":")[0].split("/")[0]
def _error_code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")
def _role_documents(iam, role_name):
    """Yield every IAM policy document (inline and managed) of a role."""
    for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        yield iam.get_role_policy(
            RoleName=role_name, PolicyName=name)["PolicyDocument"]
    for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
        arn = p["PolicyArn"]
        version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        yield iam.get_policy_version(
            PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
def _dynamodb_access(doc):
    """Yield (resource, action) for each Allow statement that touches DynamoDB."""
    for st in _as_list(doc.get("Statement", [])):
        if st.get("Effect") != "Allow":
            continue
        actions = [a for a in _as_list(st.get("Action", []))
                   if a == "*" or a.lower().startswith("dynamodb:")]
        for res in _as_list(st.get("Resource", [])):
            for a in actions:
                yield res, a
def _is_wildcard(action: str, resource: str) -> bool:
    return action == "*" or action.endswith(":*") or resource == "*"
def _bucket_exposure(s3, bucket):
    """Return a reason string if anyone on the internet can read the bucket."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        if all(cfg.get(k) for k in ("BlockPublicAcls", "BlockPublicPolicy",
                                    "IgnorePublicAcls", "RestrictPublicBuckets")):
            return None  # Block Public Access is fully on
    except ClientError as e:
        if _error_code(e) != "NoSuchPublicAccessBlockConfiguration":
            raise
    try:
        if s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]:
            return "bucket policy allows Principal '*'"
    except ClientError as e:
        if _error_code(e) != "NoSuchBucketPolicy":
            raise
    for grant in s3.get_bucket_acl(Bucket=bucket)["Grants"]:
        if (grant.get("Grantee", {}).get("URI") == ALL_USERS
                and grant.get("Permission") in ("READ", "FULL_CONTROL")):
            return "ACL grants AllUsers read access"
    return None
def scan_stack(stack_name: str, region: str = None) -> dict:
    session = boto3.session.Session(region_name=region)
    cfn = session.client("cloudformation")
    apigw = session.client("apigatewayv2")
    lam = session.client("lambda")
    iam = session.client("iam")
    ddb = session.client("dynamodb")
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    logical = {r["PhysicalResourceId"]: r["LogicalResourceId"] for r in resources}
    api_ids = [r["PhysicalResourceId"] for r in resources
               if r["ResourceType"] == "AWS::ApiGatewayV2::Api"]
    table_names = [r["PhysicalResourceId"] for r in resources
                   if r["ResourceType"] == "AWS::DynamoDB::Table"]
    function_names = [r["PhysicalResourceId"] for r in resources
                      if r["ResourceType"] == "AWS::Lambda::Function"]
    bucket_names = [r["PhysicalResourceId"] for r in resources
                    if r["ResourceType"] == "AWS::S3::Bucket"]
    nodes, edges = {}, []
    def node(nid, **attrs):
        nodes.setdefault(nid, {"id": nid, **attrs})
    def edge(src, dst, label, resource=None, **extra):
        e = {"from": src, "to": dst, "label": label}
        if resource:
            e["resource"] = resource
        e.update(extra)
        edges.append(e)
    def lambda_node(function_name):
        nid = logical.get(function_name, function_name)
        node(nid, name=function_name, kind="lambda")
        return nid
    # 1. DynamoDB tables (sensitivity comes from the table's tag)
    for t in table_names:
        arn = ddb.describe_table(TableName=t)["Table"]["TableArn"]
        tags = {x["Key"]: x["Value"]
                for x in ddb.list_tags_of_resource(ResourceArn=arn)["Tags"]}
        attrs = {"name": t, "kind": "dynamodb"}
        if "sensitivity" in tags:
            attrs["sensitivity"] = tags["sensitivity"]
        node(logical[t], **attrs)
    # 2. API Gateway: routes, integrations and authorizers
    for api_id in api_ids:
        api = apigw.get_api(ApiId=api_id)
        api_node = logical[api_id]
        attrs = {"name": api["Name"], "kind": "apigateway"}
        if not api.get("DisableExecuteApiEndpoint", False):
            attrs["trust"] = "public"
        node(api_node, **attrs)
        integrations = {i["IntegrationId"]: i
                        for i in apigw.get_integrations(ApiId=api_id)["Items"]}
        authorizers = {a["AuthorizerId"]: a
                       for a in apigw.get_authorizers(ApiId=api_id)["Items"]}
        for route in apigw.get_routes(ApiId=api_id)["Items"]:
            key = route["RouteKey"]
            route_res = logical.get(route.get("RouteId"))
            integ = integrations.get(route.get("Target", "").split("/")[-1], {})
            uri = integ.get("IntegrationUri", "")
            if ":function:" not in uri:
                print(f"warning: route '{key}' does not target a Lambda; skipped",
                      file=sys.stderr)
                continue
            target = lambda_node(_lambda_name(uri))
            auth_type = route.get("AuthorizationType", "NONE")
            if auth_type == "NONE":
                edge(api_node, target, key, route_res)
                continue
            if auth_type == "CUSTOM":
                auth = authorizers[route["AuthorizerId"]]
                auth_node = lambda_node(_lambda_name(auth["AuthorizerUri"]))
            else:  # JWT or AWS_IAM: no Lambda, so add a virtual auth node
                auth_node = f"{auth_type.lower()}-auth"
                node(auth_node, name=auth_node, kind=auth_type.lower() + "-authorizer")
            nodes[auth_node]["role"] = "auth"
            edge(api_node, auth_node, key, route_res)
            edge(auth_node, target, "authorizes", route_res)
    # 3. Every Lambda in the stack, and its Function URL if it has one
    for fn in function_names:
        fn_node = lambda_node(fn)
        try:
            cfg = lam.get_function_url_config(FunctionName=fn)
        except ClientError as e:
            if _error_code(e) == "ResourceNotFoundException":
                continue  # no Function URL
            print(f"warning: cannot read the Function URL of '{fn}': "
                  f"{_error_code(e)}", file=sys.stderr)
            continue
        auth = cfg.get("AuthType", "AWS_IAM")
        url_node = f"{fn_node}Url"
        attrs = {"name": url_node, "kind": "lambda-url", "trust": "public",
                 "auth_type": auth}
        if auth != "NONE":
            attrs["role"] = "auth"  # AWS_IAM: callers must sign requests
        node(url_node, **attrs)
        edge(url_node, fn_node, f"Function URL (AuthType {auth})", fn_node)
    # 4. IAM: which tables can each Lambda reach?
    for nid, n in list(nodes.items()):
        if n["kind"] != "lambda":
            continue
        role = lam.get_function_configuration(FunctionName=n["name"])["Role"].split("/")[-1]
        access = {}
        for doc in _role_documents(iam, role):
            for res, action in _dynamodb_access(doc):
                if res == "*":
                    targets = table_names
                elif ":table/" in res:
                    targets = [res.split(":table/")[1].split("/")[0]]
                else:
                    continue
                for t in targets:
                    entry = access.setdefault(t, {"actions": set(), "wildcard": False})
                    entry["actions"].add(action)
                    entry["wildcard"] = entry["wildcard"] or _is_wildcard(action, res)
        for t, entry in access.items():
            if t in logical:
                extra = {"wildcard": True} if entry["wildcard"] else {}
                edge(nid, logical[t], ", ".join(sorted(entry["actions"])), nid, **extra)
    # 5. S3 buckets that anyone on the internet can read
    if bucket_names:
        s3 = session.client("s3")
        for b in bucket_names:
            attrs = {"name": b, "kind": "s3"}
            try:
                tags = {x["Key"]: x["Value"]
                        for x in s3.get_bucket_tagging(Bucket=b)["TagSet"]}
            except ClientError as e:
                if _error_code(e) != "NoSuchTagSet":
                    raise
                tags = {}
            if "sensitivity" in tags:
                attrs["sensitivity"] = tags["sensitivity"]
            reason = _bucket_exposure(s3, b)
            if reason:
                attrs.update(public_read=True, exposure_reason=reason,
                             exposure_resource=logical[b])
            node(logical[b], **attrs)
    return {"nodes": list(nodes.values()), "edges": edges}
def main():
    p = argparse.ArgumentParser(description="Scan a deployed stack into a graph file")
    p.add_argument("stack", help="CloudFormation stack name")
    p.add_argument("--region", help="AWS region (default: from aws configure)")
    p.add_argument("--out", help="output file (default: graphs/live-<stack>.yml)")
    a = p.parse_args()
    graph = scan_stack(a.stack, a.region)
    out = a.out or f"graphs/live-{a.stack}.yml"
    Path(out).write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")
    print(f"Scanned '{a.stack}': {len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges -> {out}")
if __name__ == "__main__":
    main()
