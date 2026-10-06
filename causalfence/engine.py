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


@dataclass
class Result:
    passed: bool
    findings: list = field(default_factory=list)

    @property
    def total_penalty(self) -> int:
        return sum(f.penalty for f in self.findings)


def _finding(rules, rule_id, path, message) -> Finding:
    r = rules[rule_id]
    return Finding(
        rule=rule_id,
        path=path,
        message=message,
        severity=r["severity"],
        penalty=r["penalty"],
        remediation=" ".join(r["remediation"].split()),
    )


def check_auth_required(G: nx.DiGraph, rules: dict) -> list:
    """Rule 1: public -> ... -> sensitive must cross an auth node."""
    auth = set(auth_nodes(G))
    findings = []
    for src in public_nodes(G):
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
                ))
    return findings


def run_all_checks(G: nx.DiGraph, rules: dict = None) -> Result:
    """Run every rule. Most severe findings come first."""
    rules = rules or load_rules()
    findings = []
    findings += check_public_db_exposure(G, rules)
    findings += check_auth_required(G, rules)
    findings.sort(key=lambda f: f.penalty, reverse=True)
    return Result(passed=not findings, findings=findings)