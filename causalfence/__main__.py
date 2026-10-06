import sys

from causalfence.loader import load_graph
from causalfence.engine import run_all_checks
from causalfence.scoring import compute_score


def main(argv) -> int:
    if len(argv) != 2:
        print("Usage: python -m causalfence <graph.yml>")
        return 2

    result = run_all_checks(load_graph(argv[1]))
    score = compute_score(result)

    print("PASS" if result.passed else "FAIL")
    print(score)
    for f in result.findings:
        print(f"[{f.severity}] {f.rule} (penalty -{f.penalty})")
        print(f"  {f.message}")
        print(f"  Fix: {f.remediation}")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))