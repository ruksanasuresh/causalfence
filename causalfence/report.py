"""Detailed report: every finding with rule, path, evidence and a fix."""
import argparse
import sys

from causalfence.engine import run_all_checks
from causalfence.loader import load_graph


def format_finding(f) -> str:
    out = [f"[{f.severity}] {f.rule} (penalty -{f.penalty})",
           f"  Path:     {' -> '.join(f.path)}",
           "  Evidence:"]
    out += [f"    - {line}" for line in f.evidence] or ["    - (none recorded)"]
    out.append(f"  Why:      {f.message}")
    out.append(f"  Fix:      {f.remediation}")
    if f.fix_snippet:
        out.append("  Copy-paste fix:")
        out += [f"    | {line}" for line in f.fix_snippet.splitlines()]
    return "\n".join(out)


def format_report(result) -> str:
    if result.passed:
        return "PASS - no findings."
    parts = [f"FAIL - {len(result.findings)} finding(s)\n"]
    parts += [format_finding(f) + "\n" for f in result.findings]
    return "\n".join(parts)


def main(argv=None):
    p = argparse.ArgumentParser(description="Detailed CausalFence report")
    p.add_argument("graph", help="graph file (live scan or parsed template)")
    a = p.parse_args(argv)
    result = run_all_checks(load_graph(a.graph))
    print(format_report(result))
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()