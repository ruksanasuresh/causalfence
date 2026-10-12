import sys
from causalfence.engine import run_all_checks
from causalfence.loader import load_graph
from causalfence.report import format_report
from causalfence.risk import assess
def main(argv) -> int:
    if len(argv) != 2:
        print("Usage: python -m causalfence <graph.yml>")
        return 2
    G = load_graph(argv[1])
    result = run_all_checks(G)
    verdict = assess(G, result)
    print("PASS" if result.passed else "FAIL")
    print(verdict.headline())
    if not result.passed:
        print()
        print(format_report(result, verdict))
    return 0 if result.passed else 1
if __name__ == "__main__":
    sys.exit(main(sys.argv))
