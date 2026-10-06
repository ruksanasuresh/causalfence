"""Rule engine: find paths from public entry points to sensitive data
that do not pass through an authentication node."""
from dataclasses import dataclass, field
import networkx as nx

from causalfence.loader import public_nodes, sensitive_nodes, auth_nodes


@dataclass
class Finding:
    rule: str            # e.g. "AUTH_BYPASS"
    path: list           # node ids, in order
    message: str


@dataclass
class Result:
    passed: bool
    findings: list = field(default_factory=list)


def check_auth_required(G: nx.DiGraph) -> Result:
    """Rule 1: public -> sensitive paths must cross an auth node."""
    auth = set(auth_nodes(G))
    findings = []

    for src in public_nodes(G):
        for dst in sensitive_nodes(G):
            for path in nx.all_simple_paths(G, src, dst):
                if not auth.intersection(path):
                    findings.append(
                        Finding(
                            rule="AUTH_BYPASS",
                            path=path,
                            message=(
                                f"Public entry '{src}' reaches sensitive "
                                f"resource '{dst}' without passing through "
                                f"an authentication node: "
                                + " -> ".join(path)
                            ),
                        )
                    )

    return Result(passed=not findings, findings=findings)


def run_all_checks(G: nx.DiGraph) -> Result:
    """Run every rule and merge the results. More rules come later."""
    findings = []
    findings += check_auth_required(G).findings
    return Result(passed=not findings, findings=findings)