import pytest
from pathlib import Path


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_api_ingest_and_query_flow(client, repo_root):
    spec_path = str(repo_root / "specs" / "juice_shop_sample.json")

    # 1. Ingest spec
    ingest_payload = {
        "target_id": "juice_shop_test",
        "base_url": "http://localhost:18001",
        "spec_source": spec_path,
    }
    resp = client.post("/v1/ingest", json=ingest_payload)
    assert resp.status_code == 202
    job_data = resp.json()
    job_id = job_data["job_id"]
    assert "job_" in job_id

    # 2. Check Job Status
    job_resp = client.get(f"/v1/ingest/{job_id}")
    assert job_resp.status_code == 200
    status_val = job_resp.json()["status"]
    assert status_val in ["queued", "parsing", "building_graph", "tagging", "done"]

    # 3. Query Graph
    graph_resp = client.get("/v1/graph/juice_shop_test")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert len(graph_data["nodes"]) >= 3
    assert graph_data["target_id"] == "juice_shop_test"

    # 4. Query Attack Surface View
    as_resp = client.get("/v1/graph/juice_shop_test/attack-surface")
    assert as_resp.status_code == 200
    as_data = as_resp.json()
    assert "tag_summary" in as_data
    assert as_data["total_nodes"] > 0

    # 5. Augment graph with discovered endpoint
    augment_payload = {
        "method": "GET",
        "path": "/api/internal/debug-env",
        "parameters": [],
    }
    aug_resp = client.post("/v1/graph/juice_shop_test/augment", json=augment_payload)
    assert aug_resp.status_code == 200
    updated_graph = aug_resp.json()
    aug_paths = [n["path"] for n in updated_graph["nodes"]]
    assert "/api/internal/debug-env" in aug_paths

    # 6. Test Refresh without changes
    refresh_payload = {
        "base_url": "http://localhost:18001",
        "spec_source": spec_path,
    }
    ref_resp = client.post("/v1/graph/juice_shop_test/refresh", json=refresh_payload)
    assert ref_resp.status_code == 200
    ref_data = ref_resp.json()
    assert ref_data["drift_detected"] is False
