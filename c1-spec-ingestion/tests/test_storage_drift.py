import pytest
from sis.models import EndpointGraph, EndpointNode, AugmentRequest
from sis.storage import GraphStorage
from sis.service import SpecIngestionService


@pytest.mark.asyncio
async def test_storage_and_drift(tmp_path):
    storage = GraphStorage(db_path=str(tmp_path / "drift.db"))
    service = SpecIngestionService(storage=storage)

    # Initial graph
    graph = EndpointGraph(
        target_id="test_target",
        graph_id="graph_test_1",
        spec_hash="hash_v1",
        nodes=[
            EndpointNode(
                id="op_test_get_item",
                method="GET",
                path="/items/{id}",
                attack_surface_tags=["idor_candidate"]
            )
        ],
        edges=[],
        created_at="2026-10-22T00:00:00",
        updated_at="2026-10-22T00:00:00",
        metadata={}
    )
    storage.save_graph(graph)
    storage.record_spec_revision("test_target", "hash_v1", {"openapi": "3.0.0", "paths": {}})

    # Retrieve
    retrieved = storage.get_graph("test_target")
    assert retrieved is not None
    assert retrieved.graph_id == "graph_test_1"
    assert len(retrieved.nodes) == 1

    # Augment with an undocumented endpoint
    augment_req = AugmentRequest(
        method="POST",
        path="/items/admin-debug",
        metadata={"discovered_by": "executor_fuzzing"}
    )
    updated_graph = await service.augment_graph("test_target", augment_req)
    assert len(updated_graph.nodes) == 2
    
    admin_node = next(n for n in updated_graph.nodes if n.path == "/items/admin-debug")
    assert "admin_surface" in admin_node.attack_surface_tags
    assert "state_mutation" in admin_node.attack_surface_tags
