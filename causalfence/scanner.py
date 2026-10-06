"""Live AWS scanner: rebuilds the architecture graph of a deployed
CloudFormation stack with Boto3 and writes it in the graph.yml format."""
import argparse
import sys
from pathlib import Path

import boto3
import yaml


def _as_list(x):
    return x if isinstance(x, list) else [x]


def _lambda_name(uri: str) -> str:
    """Extract the function name from a Lambda ARN or an API Gateway invoke URI."""
    return uri.split(":function:")[1].split(":")[0].split("/")[0]


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

    nodes, edges = {}, []

    def node(nid, **attrs):
        nodes.setdefault(nid, {"id": nid, **attrs})

    def edge(src, dst, label):
        edges.append({"from": src, "to": dst, "label": label})

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
            integ = integrations.get(route.get("Target", "").split("/")[-1], {})
            uri = integ.get("IntegrationUri", "")
            if ":function:" not in uri:
                print(f"warning: route '{key}' does not target a Lambda; skipped",
                      file=sys.stderr)
                continue
            target = lambda_node(_lambda_name(uri))

            auth_type = route.get("AuthorizationType", "NONE")
            if auth_type == "NONE":
                edge(api_node, target, key)
                continue

            if auth_type == "CUSTOM":
                auth = authorizers[route["AuthorizerId"]]
                auth_node = lambda_node(_lambda_name(auth["AuthorizerUri"]))
            else:  # JWT or AWS_IAM: no Lambda, so add a virtual auth node
                auth_node = f"{auth_type.lower()}-auth"
                node(auth_node, name=auth_node, kind=auth_type.lower() + "-authorizer")
            nodes[auth_node]["role"] = "auth"
            edge(api_node, auth_node, key)
            edge(auth_node, target, "authorizes")

    # 3. IAM: which tables can each Lambda reach?
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
                    access.setdefault(t, set()).add(action)
        for t, actions in access.items():
            if t in logical:
                edge(nid, logical[t], ", ".join(sorted(actions)))

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