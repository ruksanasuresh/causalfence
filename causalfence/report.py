"""Detailed report: every finding with rule, path, evidence and a fix."""
import argparse
import sys

from causalfence.engine import run_all_checks
from causalfence.loader import load_graph
from causalfence.risk import assess


def format_finding(f, item=None) -> str:
    out = [f"[{f.severity}] {f.rule}",
           f"  Path:     {' -> '.join(f.path)}"]
    if item is not None:
        out.append(f"  Risk:     {item.explain()}")
    out.append("  Evidence:")
    out += [f"    - {line}" for line in f.evidence] or ["    - (none recorded)"]
    out.append(f"  Why:      {f.message}")
    out.append(f"  Fix:      {f.remediation}")
    if f.fix_snippet:
        out.append("  Copy-paste fix:")
        out += [f"    | {line}" for line in f.fix_snippet.splitlines()]
    return "\n".join(out)


def format_report(result, verdict=None) -> str:
    if result.passed:
        return "PASS - no findings."
    items = verdict.items if verdict else [None] * len(result.findings)
    parts = [f"FAIL - {len(result.findings)} finding(s)\n"]
    parts += [format_finding(f, i) + "\n" for f, i in zip(result.findings, items)]
    return "\n".join(parts)


def main(argv=None):
    p = argparse.ArgumentParser(description="Detailed CausalFence report")
    p.add_argument("graph", help="graph file (live scan or parsed template)")
    a = p.parse_args(argv)
    G = load_graph(a.graph)
    result = run_all_checks(G)
    verdict = assess(G, result)
    print(verdict.headline())
    print()
    print(format_report(result, verdict))
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()