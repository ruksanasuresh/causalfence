import sys
import tempfile
from pathlib import Path

import streamlit as st
import yaml

# Make "causalfence" importable when Streamlit runs this file
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from causalfence.loader import load_graph
from causalfence.engine import run_all_checks
from causalfence.scoring import compute_score

SCORE_COLORS = {"SAFE": "green", "LOW RISK": "orange",
                "MEDIUM RISK": "orange", "HIGH RISK": "red"}


def esc(text) -> str:
    return str(text).replace('"', "'")


def build_dot(G, findings) -> str:
    """Graphviz diagram. Edges on a dangerous path are drawn in red."""
    bad_edges = set()
    for f in findings:
        bad_edges.update(zip(f.path, f.path[1:]))

    lines = ["digraph G {", "rankdir=LR;",
             'node [shape=box, style="rounded,filled", fontname="Helvetica"];']
    for n, d in G.nodes(data=True):
        if d.get("sensitivity"):
            color = "#f8b4b4"      # sensitive data
        elif d.get("trust") == "public":
            color = "#fde2a7"      # public entry point
        elif d.get("role") == "auth":
            color = "#b7e4c7"      # authentication
        else:
            color = "#e5e7eb"
        label = f'{d.get("name", n)}\\n({d.get("kind", "")})'
        lines.append(f'"{esc(n)}" [label="{esc(label)}", fillcolor="{color}"];')
    for u, v, d in G.edges(data=True):
        style = 'color="red", penwidth=3' if (u, v) in bad_edges else 'color="#555555"'
        lines.append(f'"{esc(u)}" -> "{esc(v)}" [label="{esc(d.get("label", ""))}", {style}];')
    lines.append("}")
    return "\n".join(lines)


st.set_page_config(page_title="CausalFence", layout="wide")
st.title("CausalFence: AWS Architecture Security Testing Dashboard")

source = st.sidebar.radio("Graph source", ["Graph file", "Scan live AWS stack"])
G = None

if source == "Graph file":
    files = sorted(p.name for p in (ROOT / "graphs").glob("*.yml"))
    choice = st.sidebar.selectbox("Choose a graph", files)
    G = load_graph(str(ROOT / "graphs" / choice))
else:
    stack = st.sidebar.text_input("CloudFormation stack name", "causalfence-broken")
    region = st.sidebar.text_input("Region", "ap-south-1")
    if st.sidebar.button("Scan now"):
        from causalfence.scanner import scan_stack
        try:
            data = scan_stack(stack, region)
            with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                             encoding="utf-8") as tmp:
                yaml.safe_dump(data, tmp, sort_keys=False)
            st.session_state["live_graph"] = tmp.name
        except Exception as e:
            st.error(f"Scan failed: {e}")
    if "live_graph" in st.session_state:
        G = load_graph(st.session_state["live_graph"])

if G is None:
    st.info("Pick a graph file, or scan a live stack from the sidebar.")
    st.stop()

result = run_all_checks(G)
score = compute_score(result)

col1, col2, col3 = st.columns(3)
col1.metric("Result", "PASS" if result.passed else "FAIL")
col2.metric("Safety Score", f"{score.value}/100")
col3.metric("Findings", len(result.findings))
st.markdown(f"### :{SCORE_COLORS.get(score.label, 'gray')}[{score.label}]")

st.subheader("Architecture")
st.graphviz_chart(build_dot(G, result.findings), use_container_width=True)
st.caption("Orange = public entry, green = authentication, "
           "pink = sensitive data, red arrows = dangerous path.")

st.subheader("Detailed findings")
if result.passed:
    st.success("No dangerous paths found.")
for f in result.findings:
    with st.expander(f"[{f.severity}] {f.rule} (penalty -{f.penalty})", expanded=True):
        st.write(f.message)
        st.code(" -> ".join(f.path))
        st.info(f"Fix: {f.remediation}")

with st.expander("Nodes and edges"):
    st.write("Nodes", [{"id": n, **d} for n, d in G.nodes(data=True)])
    st.write("Edges", [{"from": u, "to": v, **d} for u, v, d in G.edges(data=True)])