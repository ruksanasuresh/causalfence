"""Rule engine: finds dangerous paths from public entry points to sensitive data."""
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import yaml

from causalfence.loader import public_nodes, sensitive_nodes, auth_nodes

RULES_FILE = Path(__file__).resolve().parent.parent / "rules.yml"


def load_rules(path=RULES_FILE) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["rules"]


@dataclass
class Finding:
    rule: str
    path: list
    message: str
    severity: str
    penalty: int
    remediation: str
    evidence: list = field(default_factory=list)  # human-readable proof lines
    fix_snippet: str = ""                          # text to copy into the template


@dataclass
class Result:
    passed: bool
    findings: list = field(default_factory=list)

    @property
    def total_penalty(self) -> int:
        return sum(f.penalty for f in self.findings)


def _where(attrs, source_file):
    """'template line 89' or 'live AWS' - where a fact was found."""
    if attrs.get("line"):
        return f"{source_file or 'template'}, line {attrs['line']}"
    return "live AWS scan"


def build_evidence(G, path):
    """One proof line per connection on the path, with file/line when known."""
    src_file = G.graph.get("source_file")
    lines = []
    for a, b in zip(path, path[1:]):
        e = G.edges[a, b]
        res = f" (resource {e['resource']})" if e.get("resource") else ""
        lines.append(f"{a} -> {b} via '{e.get('label', '')}'{res} "
                     f"[{_where(e, src_file)}]")
    return lines


def _fix_context(G, path, edge=None):
    """Details that fill the {resource}/{line} placeholders of a fix snippet."""
    e = edge or (G.edges[path[0], path[1]] if len(path) > 1 else {})
    return {"resource": e.get("resource") or "<your route>",
            "line": e.get("line") or "?",
            "where": f"line {e['line']}" if e.get("line") else "live stack",
            "sink": path[-1],
            "label": e.get("label", "")}
def _finding(rules, rule_id, path, message, G=None, evidence=None,
             context=None) -> Finding:
    """`evidence` / `context` override the defaults taken from the path edges."""
    r = rules[rule_id]
    snippet = ""
    if G is not None:
        if evidence is None:
            evidence = build_evidence(G, path)
        ctx = context or _fix_context(G, path)
        snippet = r.get("fix_snippet", "").format(**ctx).rstrip()
    evidence = evidence or []
    return Finding(
        rule=rule_id,
        path=path,
        message=message,
        severity=r["severity"],
        penalty=r["penalty"],
        remediation=" ".join(r["remediation"].split()),
        evidence=evidence,
        fix_snippet=snippet,
    )


def _is_open_url(G, n) -> bool:
    d = G.nodes[n]
    return d.get("kind") == "lambda-url" and str(d.get("auth_type", "")).upper() == "NONE"
def check_auth_required(G: nx.DiGraph, rules: dict) -> list:
    """Rule 1: public -> ... -> sensitive must cross an auth node."""
    auth = set(auth_nodes(G))
    findings = []
    for src in public_nodes(G):
        if _is_open_url(G, src):
            continue  # reported by LAMBDA_URL_OPEN instead
        for dst in sensitive_nodes(G):
            for path in nx.all_simple_paths(G, src, dst):
                if len(path) == 2:
                    continue  # direct link: reported by Rule 2 instead
                if not auth.intersection(path):
                    findings.append(_finding(
                        rules, "AUTH_BYPASS", path,
                        f"Public entry '{src}' reaches sensitive resource "
                        f"'{dst}' without passing through an authentication "
                        f"node: " + " -> ".join(path),
                        G,
                    ))
    return findings


def check_public_db_exposure(G: nx.DiGraph, rules: dict) -> list:
    """Rule 2: a public node connects directly to a sensitive resource."""
    findings = []
    for src in public_nodes(G):
        for dst in sensitive_nodes(G):
            if G.has_edge(src, dst):
                findings.append(_finding(
                    rules, "PUBLIC_DB_EXPOSURE", [src, dst],
                    f"Public entry '{src}' is directly connected to "
                    f"sensitive resource '{dst}': {src} -> {dst}",
                    G,
                ))
    return findings


def check_lambda_url_open(G: nx.DiGraph, rules: dict) -> list:
    """Rule 3: a Lambda Function URL with AuthType NONE reaches sensitive data."""
    findings = []
    for src in [n for n in G.nodes if _is_open_url(G, n)]:
        for dst in sensitive_nodes(G):
            for path in nx.all_simple_paths(G, src, dst):
                e = G.edges[path[0], path[1]]
                findings.append(_finding(
                    rules, "LAMBDA_URL_OPEN", path,
                    f"Function URL '{src}' has AuthType NONE, so anyone on the "
                    f"internet can invoke it and reach '{dst}': "
                    + " -> ".join(path),
                    G, context=_fix_context(G, path, e)))
    return findings
def check_overbroad_iam(G: nx.DiGraph, rules: dict) -> list:
    """Rule 4: a public entry reaches sensitive data through a wildcard IAM grant."""
    findings, seen = [], set()
    for src in public_nodes(G):
        for dst in sensitive_nodes(G):
            for path in nx.all_simple_paths(G, src, dst):
                for a, b in zip(path, path[1:]):
                    e = G.edges[a, b]
                    if e.get("wildcard") and (a, b) not in seen:
                        seen.add((a, b))
                        findings.append(_finding(
                            rules, "OVERBROAD_IAM", path,
                            f"'{a}' is allowed '{e.get('label')}' on '{b}' "
                            f"(wildcard) and is reachable from public entry "
                            f"'{src}'. Grant only the actions the code needs.",
                            G, context=_fix_context(G, path, e)))
    return findings
def check_public_s3(G: nx.DiGraph, rules: dict) -> list:
    """Rule 5: an S3 bucket anyone on the internet can read."""
    findings = []
    for n, d in G.nodes(data=True):
        if d.get("kind") == "s3" and d.get("public_read"):
            where = d.get("exposure_line")
            loc = (f"{G.graph.get('source_file') or 'template'}, line {where}"
                   if where else "live AWS scan")
            evidence = [f"Bucket '{n}' is publicly readable: "
                        f"{d.get('exposure_reason')} "
                        f"(resource {d.get('exposure_resource')}) [{loc}]"]
            findings.append(_finding(
                rules, "PUBLIC_S3_BUCKET", [n],
                f"S3 bucket '{n}' can be read by anyone on the internet "
                f"({d.get('exposure_reason')}).",
                G, evidence=evidence,
                context={"resource": d.get("exposure_resource") or n,
                         "line": where or "?", "label": "",
                         "where": f"line {where}" if where else "live stack",
                         "sink": n}))
    return findings
def run_all_checks(G: nx.DiGraph, rules: dict = None) -> Result:
    """Run every rule. Most severe findings come first."""
    rules = rules or load_rules()
    findings = []
    findings += check_public_db_exposure(G, rules)
    findings += check_auth_required(G, rules)
    findings += check_lambda_url_open(G, rules)
    findings += check_overbroad_iam(G, rules)
    findings += check_public_s3(G, rules)
    findings.sort(key=lambda f: f.penalty, reverse=True)
    return Result(passed=not findings, findings=findings)