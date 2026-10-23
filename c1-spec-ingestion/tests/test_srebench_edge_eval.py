import json
import pytest
from pathlib import Path

from sis.adapters.srebench import SREBenchAdapter
from sis.normalizer import SpecNormalizer
from sis.graph_builder import GraphBuilder


@pytest.mark.asyncio
async def test_srebench_ground_truth_chain_coverage(repo_root):
    """
    Evaluates SIS edge inference against ground truth exploit chains (SRE-01, SRE-02).
    Checks that cross-service dependency edges exist between Auth, Users, and Vault.
    """
    spec_path = str(repo_root / "specs" / "srebench_openapi.json")
    adapter = SREBenchAdapter()
    raw_spec, metadata = await adapter.load_spec("srebench_eval", "http://localhost:18002", spec_source=spec_path)

    normalizer = SpecNormalizer()
    normalized, spec_hash = normalizer.normalize(raw_spec)

    builder = GraphBuilder()
    graph = builder.build_graph("srebench_eval", spec_hash, normalized, metadata)

    node_map = {n.id: n for n in graph.nodes}
    path_to_node_id = {n.path: n.id for n in graph.nodes}

    # Verify key operations exist
    assert "/auth/v1/exchange-token" in path_to_node_id
    assert "/users/v1/profile/{user_id}" in path_to_node_id
    assert "/vault/v1/documents/{doc_id}" in path_to_node_id

    auth_id = path_to_node_id["/auth/v1/exchange-token"]
    user_id = path_to_node_id["/users/v1/profile/{user_id}"]
    vault_id = path_to_node_id["/vault/v1/documents/{doc_id}"]

    # Check edges
    # Hop 1: Auth -> User (exchange-token -> profile/{user_id})
    auth_to_user_edges = [
        e for e in graph.edges if e.from_node == auth_id and e.to_node == user_id
    ]
    assert len(auth_to_user_edges) > 0, "Missing dependency edge from Auth to Users service"

    # Hop 2: User -> Vault (profile -> documents/{doc_id})
    user_to_vault_edges = [
        e for e in graph.edges if e.from_node == user_id and e.to_node == vault_id
    ]
    assert len(user_to_vault_edges) > 0, "Missing dependency edge from Users to Vault service"

    # Check cross-service flags
    assert auth_to_user_edges[0].metadata["cross_service"] is True
    assert user_to_vault_edges[0].metadata["cross_service"] is True

    # Check attack surface tagging on Vault endpoint
    vault_node = node_map[vault_id]
    assert "idor_candidate" in vault_node.attack_surface_tags
    assert any("cross_service_param" in t for t in vault_node.attack_surface_tags)
