"""Load an architecture description (YAML) into a directed graph."""
import networkx as nx
import yaml


class GraphError(Exception):
    """Raised when the graph file is invalid."""


def load_graph(path: str) -> nx.DiGraph:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    G = nx.DiGraph()

    # Nodes: every attribute except "id" is stored on the node
    for node in data.get("nodes", []):
        if "id" not in node:
            raise GraphError(f"Node without an id: {node}")
        attrs = {k: v for k, v in node.items() if k != "id"}
        G.add_node(node["id"], **attrs)

    # Edges: both ends must exist as nodes
    for edge in data.get("edges", []):
        src, dst = edge.get("from"), edge.get("to")
        for end in (src, dst):
            if end not in G:
                raise GraphError(f"Edge refers to unknown node '{end}': {edge}")
        G.add_edge(src, dst, label=edge.get("label", ""))

    return G


# Helpers the rule engine will use in Phase 3
def public_nodes(G):
    return [n for n, d in G.nodes(data=True) if d.get("trust") == "public"]


def sensitive_nodes(G):
    return [n for n, d in G.nodes(data=True) if d.get("sensitivity")]


def auth_nodes(G):
    return [n for n, d in G.nodes(data=True) if d.get("role") == "auth"]