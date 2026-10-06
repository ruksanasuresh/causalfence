from causalfence.loader import (
    load_graph, public_nodes, sensitive_nodes, auth_nodes,
)


def test_safe_graph_loads():
    G = load_graph("graphs/safe.yml")
    assert G.number_of_nodes() == 4
    assert G.number_of_edges() == 3
    assert public_nodes(G) == ["public-api"]
    assert sensitive_nodes(G) == ["phi-table"]
    assert auth_nodes(G) == ["auth-lambda"]


def test_bypass_graph_has_direct_edge():
    G = load_graph("graphs/bypass.yml")
    assert G.has_edge("public-api", "patient-lambda")