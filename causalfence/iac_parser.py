"""IaC parser: builds the architecture graph straight from a CloudFormation /
SAM template (no AWS account or credentials needed).

    python -m causalfence.iac_parser infra/template.yaml --param AuthMode=broken

The output uses the same graph.yml format as the Boto3 scanner, so the
existing loader and rule engine work on it unchanged.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

NOVALUE = object()  # marker for { Ref: AWS::NoValue }

# Resource types the parser understands.
SUPPORTED = {
    "AWS::DynamoDB::Table", "AWS::Serverless::Function", "AWS::Lambda::Function",
    "AWS::ApiGatewayV2::Api", "AWS::ApiGatewayV2::Integration",
    "AWS::ApiGatewayV2::Authorizer", "AWS::ApiGatewayV2::Route",
}
# Types that carry no routing/data-access information for the current rules.
IGNORED = {
    "AWS::ApiGatewayV2::Stage", "AWS::Lambda::Permission",
}

SAM_DYNAMODB_POLICIES = {
    "DynamoDBCrudPolicy", "DynamoDBReadPolicy", "DynamoDBWritePolicy",
    "DynamoDBReconfigurePolicy",
}


# ---------------------------------------------------------------- YAML --
class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that understands CloudFormation short tags (!Ref, !Sub ...)."""


def _intrinsic(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "Condition":
        return {"Condition": value}
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {f"Fn::{suffix}": value}


_CfnLoader.add_multi_constructor("!", _intrinsic)


def _read_template(path):
    text = Path(path).read_text(encoding="utf-8")
    template = yaml.load(text, Loader=_CfnLoader) or {}
    # Line number of each resource (1-based) for evidence in findings.
    lines = {}
    root = yaml.compose(text, Loader=_CfnLoader)
    if isinstance(root, yaml.MappingNode):
        for key, val in root.value:
            if key.value == "Resources" and isinstance(val, yaml.MappingNode):
                for rkey, _ in val.value:
                    lines[rkey.value] = rkey.start_mark.line + 1
    return template, lines


# ------------------------------------------------------ intrinsic logic --
class _Context:
    def __init__(self, template, overrides):
        self.params = {}
        for name, spec in (template.get("Parameters") or {}).items():
            if name in overrides:
                self.params[name] = overrides[name]
            elif "Default" in spec:
                self.params[name] = spec["Default"]
        unknown = set(overrides) - set(template.get("Parameters") or {})
        if unknown:
            raise ValueError(f"Unknown parameter(s): {', '.join(sorted(unknown))}")
        self.conditions = {}
        self._raw_conditions = template.get("Conditions") or {}
        for name in self._raw_conditions:
            self.condition(name)

    def condition(self, name):
        if name not in self.conditions:
            self.conditions[name] = bool(self.resolve(self._raw_conditions[name]))
        return self.conditions[name]

    def resolve(self, value):
        """Evaluate conditions, parameters and Fn::If; keep resource references."""
        if isinstance(value, list):
            return [x for x in (self.resolve(v) for v in value) if x is not NOVALUE]
        if not isinstance(value, dict):
            return value
        if len(value) == 1:
            (key, arg), = value.items()
            if key == "Ref":
                if arg == "AWS::NoValue":
                    return NOVALUE
                if arg in self.params:
                    return self.params[arg]
                return value  # resource reference: resolved later by refs()
            if key == "Condition":
                return self.condition(arg)
            if key == "Fn::If":
                cond, yes, no = arg
                chosen = yes if self.condition(cond) else no
                return self.resolve(chosen)
            if key == "Fn::Equals":
                a, b = (self.resolve(x) for x in arg)
                return a == b
            if key == "Fn::Not":
                return not self.resolve(arg[0])
            if key == "Fn::And":
                return all(self.resolve(x) for x in arg)
            if key == "Fn::Or":
                return any(self.resolve(x) for x in arg)
            if key == "Fn::Sub":
                text = arg[0] if isinstance(arg, list) else arg
                if isinstance(text, str):
                    for p, v in self.params.items():
                        text = text.replace("${" + p + "}", str(v))
                return {"Fn::Sub": text}
        out = {}
        for k, v in value.items():
            r = self.resolve(v)
            if r is not NOVALUE:
                out[k] = r
        return out


_SUB_VAR = re.compile(r"\$\{([A-Za-z0-9]+)(?:\.[A-Za-z0-9.]+)?\}")


def _refs(value, known):
    """Logical ids of resources mentioned in a resolved value, in order."""
    found = []

    def add(x):
        if x in known and x not in found:
            found.append(x)

    def walk(v):
        if isinstance(v, dict):
            if set(v) == {"Ref"}:
                add(v["Ref"])
            elif set(v) == {"Fn::GetAtt"}:
                add(v["Fn::GetAtt"][0])
            elif set(v) == {"Fn::Sub"}:
                for name in _SUB_VAR.findall(v["Fn::Sub"]):
                    add(name)
            else:
                for x in v.values():
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(value)
    return found


# ------------------------------------------------------------- parsing --
def _tags(props):
    tags = props.get("Tags") or []
    if isinstance(tags, dict):
        return tags
    return {t.get("Key"): t.get("Value") for t in tags if isinstance(t, dict)}


def parse_template(path, params=None):
    """Return {'nodes': [...], 'edges': [...]} for the template at `path`.

    `params` overrides template parameters, e.g. {"AuthMode": "broken"}.
    """
    template, lines = _read_template(path)
    ctx = _Context(template, params or {})

    # Keep only resources whose Condition is true.
    resources = {}
    for rid, res in (template.get("Resources") or {}).items():
        cond = res.get("Condition")
        if cond is None or ctx.condition(cond):
            resources[rid] = {
                "Type": res.get("Type"),
                "Properties": ctx.resolve(res.get("Properties") or {}),
            }
    known = set(resources)

    nodes, edges, warnings = {}, [], []

    def node(nid, **attrs):
        nodes.setdefault(nid, {"id": nid, **attrs})
        return nodes[nid]

    def edge(src, dst, label, resource):
        edges.append({"from": src, "to": dst, "label": label,
                      "resource": resource, "line": lines.get(resource)})

    by_type = lambda t: {r: v for r, v in resources.items() if v["Type"] == t}

    # 1. Tables, functions, APIs -> nodes
    for rid, r in by_type("AWS::DynamoDB::Table").items():
        attrs = {"name": rid, "kind": "dynamodb", "source": "template", "line": lines.get(rid)}
        sensitivity = _tags(r["Properties"]).get("sensitivity")
        if sensitivity:
            attrs["sensitivity"] = sensitivity
        node(rid, **attrs)
    for t in ("AWS::Serverless::Function", "AWS::Lambda::Function"):
        for rid in by_type(t):
            node(rid, name=rid, kind="lambda", source="template", line=lines.get(rid))
    for rid, r in by_type("AWS::ApiGatewayV2::Api").items():
        attrs = {"name": rid, "kind": "apigateway", "source": "template", "line": lines.get(rid)}
        if not r["Properties"].get("DisableExecuteApiEndpoint", False):
            attrs["trust"] = "public"
        node(rid, **attrs)

    # 2. Routes, integrations, authorizers -> edges
    integrations = {}
    for rid, r in by_type("AWS::ApiGatewayV2::Integration").items():
        targets = [x for x in _refs(r["Properties"].get("IntegrationUri"), known)
                   if resources[x]["Type"] in ("AWS::Serverless::Function", "AWS::Lambda::Function")]
        integrations[rid] = targets[0] if targets else None
    authorizers = {}
    for rid, r in by_type("AWS::ApiGatewayV2::Authorizer").items():
        targets = [x for x in _refs(r["Properties"].get("AuthorizerUri"), known)
                   if resources[x]["Type"] in ("AWS::Serverless::Function", "AWS::Lambda::Function")]
        authorizers[rid] = targets[0] if targets else None

    for rid, r in by_type("AWS::ApiGatewayV2::Route").items():
        p = r["Properties"]
        api = next((x for x in _refs(p.get("ApiId"), known)
                    if resources[x]["Type"] == "AWS::ApiGatewayV2::Api"), None)
        integ = next((x for x in _refs(p.get("Target"), known) if x in integrations), None)
        target = integrations.get(integ)
        key = p.get("RouteKey", rid)
        if api is None or target is None:
            warnings.append(f"route '{key}' ({rid}) does not target a Lambda; skipped")
            continue

        auth_type = p.get("AuthorizationType", "NONE")
        if auth_type == "NONE":
            edge(api, target, key, rid)
            continue
        if auth_type == "CUSTOM":
            auth_id = next((x for x in _refs(p.get("AuthorizerId"), known) if x in authorizers), None)
            auth_node = authorizers.get(auth_id)
            if auth_node is None:
                # CUSTOM with no usable authorizer is not real authentication
                warnings.append(f"route '{key}' is CUSTOM but has no authorizer; treated as open")
                edge(api, target, key, rid)
                continue
        else:  # JWT or AWS_IAM: virtual auth node, like the scanner
            auth_node = f"{auth_type.lower()}-auth"
            node(auth_node, name=auth_node, kind=auth_type.lower() + "-authorizer", source="template")
        nodes[auth_node]["role"] = "auth"
        edge(api, auth_node, key, rid)
        edge(auth_node, target, "authorizes", rid)

    # 3. Function -> table access (SAM policy templates and inline statements)
    for rid, r in resources.items():
        if r["Type"] not in ("AWS::Serverless::Function", "AWS::Lambda::Function"):
            continue
        policies = r["Properties"].get("Policies") or []
        if isinstance(policies, dict):
            policies = [policies]
        tables = {t for t in by_type("AWS::DynamoDB::Table")}
        for pol in policies:
            if not isinstance(pol, dict):
                continue
            for name in SAM_DYNAMODB_POLICIES & set(pol):
                for t in _refs(pol[name], known):
                    if t in tables:
                        edge(rid, t, name, rid)
            if "Statement" in pol:
                for st in pol["Statement"] if isinstance(pol["Statement"], list) else [pol["Statement"]]:
                    if st.get("Effect") != "Allow":
                        continue
                    acts = st.get("Action", [])
                    acts = acts if isinstance(acts, list) else [acts]
                    acts = [a for a in acts if a == "*" or str(a).lower().startswith("dynamodb:")]
                    if not acts:
                        continue
                    res = st.get("Resource", [])
                    res = res if isinstance(res, list) else [res]
                    hit = set()
                    for x in res:
                        hit |= set(_refs(x, known)) & tables
                        if x == "*":
                            hit |= tables
                    for t in sorted(hit):
                        edge(rid, t, ", ".join(sorted(acts)), rid)

    for rid, r in resources.items():
        if r["Type"] not in SUPPORTED | IGNORED:
            warnings.append(f"{rid} ({r['Type']}) is not understood yet and was skipped")

    return {"nodes": list(nodes.values()), "edges": edges, "warnings": warnings}


def main(argv=None):
    p = argparse.ArgumentParser(description="Build a graph file from a CloudFormation/SAM template")
    p.add_argument("template", help="path to template.yaml")
    p.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                   help="override a template parameter (repeatable)")
    p.add_argument("--out", help="output file (default: graphs/template-<params>.yml)")
    a = p.parse_args(argv)

    overrides = dict(x.split("=", 1) for x in a.param)
    graph = parse_template(a.template, overrides)
    warnings = graph.pop("warnings")
    graph["source_file"] = str(a.template).replace("\\", "/")
    suffix = "-".join(overrides.values()) or "default"
    out = a.out or f"graphs/template-{suffix}.yml"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(yaml.safe_dump(graph, sort_keys=False), encoding="utf-8")
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(f"Parsed '{a.template}': {len(graph['nodes'])} nodes, "
          f"{len(graph['edges'])} edges -> {out}")


if __name__ == "__main__":
    main()