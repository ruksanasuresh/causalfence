"""CI gate: scan CloudFormation/SAM templates before they are deployed.
    python -m causalfence.ci --template infra/template.yaml --comment out.md
No AWS account or credentials needed. Writes a Markdown report (used for the
pull-request comment) and exits 1 if any template has a finding.
"""
import argparse
import sys
import tempfile
from pathlib import Path
import yaml
from causalfence.engine import run_all_checks
from causalfence.iac_parser import parse_template
from causalfence.loader import load_graph
from causalfence.report import format_finding
from causalfence.risk import assess
MARKER = "<!-- causalfence-gate -->"
def scan_template(path, params=None):
    """Parse one template and run every rule. Returns (result, verdict)."""
    graph = parse_template(path, params or {})
    graph.pop("warnings", None)
    graph["source_file"] = str(path).replace("\\", "/")
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                     encoding="utf-8") as tmp:
        yaml.safe_dump(graph, tmp, sort_keys=False)
    G = load_graph(tmp.name)
    Path(tmp.name).unlink()
    result = run_all_checks(G)
    return result, assess(G, result)
def build_markdown(entries) -> str:
    """entries: list of (template_path, result, verdict, error)."""
    failed = any(err or not res.passed for _, res, _, err in entries)
    lines = [MARKER,
             "## CausalFence security gate: " + ("FAIL - merge blocked" if failed else "PASS"),
             ""]
    for path, res, verdict, err in entries:
        lines.append(f"### `{path}`")
        if err:
            lines += [f"**Could not scan this template:** {err}", ""]
            continue
        lines += [f"**{verdict.headline()}**", ""]
        for f, item in zip(res.findings, verdict.items):
            lines += [f"<details open><summary><b>[{f.severity}] {f.rule}</b> - "
                      f"{' -> '.join(f.path)}</summary>",
                      "",
                      "```text",
                      format_finding(f, item),
                      "```",
                      "</details>",
                      ""]
    lines.append("_Scanned from the template only, before deploy (no AWS credentials). "
                 "The check stays red until every finding is fixed._")
    return "\n".join(lines) + "\n"
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="CausalFence pre-deploy gate")
    p.add_argument("--template", action="append", required=True,
                   help="CloudFormation/SAM template to scan (repeatable)")
    p.add_argument("--param", action="append", default=[], metavar="NAME=VALUE",
                   help="template parameter override (default: the template's own defaults)")
    p.add_argument("--comment", help="write the Markdown report to this file")
    a = p.parse_args(argv)
    params = dict(x.split("=", 1) for x in a.param)
    entries, crashed = [], False
    for path in a.template:
        try:
            result, verdict = scan_template(path, params)
            entries.append((path, result, verdict, None))
        except Exception as e:
            crashed = True
            entries.append((path, None, None, f"{type(e).__name__}: {e}"))
    md = build_markdown(entries)
    if a.comment:
        Path(a.comment).write_text(md, encoding="utf-8")
    print(md)
    if crashed:
        return 2
    return 1 if any(not res.passed for _, res, _, _ in entries) else 0
if __name__ == "__main__":
    sys.exit(main())
