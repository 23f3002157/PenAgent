def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_generate_and_queue_flow(client, sample_attack_surface):
    target_id = sample_attack_surface["target_id"]

    # Pre-cache attack surface in service
    from hgs.api import service as api_service
    api_service.set_cached_attack_surface(target_id, sample_attack_surface)

    # 1. Generate hypotheses
    payload = {
        "target_id": target_id,
        "mode": "initial",
        "knowledge_state_delta": {},
        "prior_findings": [],
        "max_hypotheses": 10,
    }
    resp = client.post("/v1/hypotheses/generate", json=payload)
    assert resp.status_code == 200
    batch = resp.json()
    assert batch["target_id"] == target_id
    assert len(batch["hypotheses"]) > 0
    batch_id = batch["batch_id"]

    # 2. Retrieve Batch
    get_batch_resp = client.get(f"/v1/hypotheses/{batch_id}")
    assert get_batch_resp.status_code == 200
    assert len(get_batch_resp.json()["hypotheses"]) > 0

    # 3. Pop Next from Queue
    pop_resp = client.get(f"/v1/queue/{target_id}/next")
    assert pop_resp.status_code == 200
    popped = pop_resp.json()
    assert popped is not None
    hyp_id = popped["id"]
    assert popped["status"] == "in_progress"

    # 4. Report Feedback on Popped Hypothesis
    feedback_payload = {
        "outcome": "confirmed_vulnerability",
        "evidence": "Leaked document doc_002 and RSA private key",
        "discovered_state": {"rsa_key": "MIIE..."},
    }
    fb_resp = client.post(f"/v1/hypotheses/{hyp_id}/feedback", json=feedback_payload)
    assert fb_resp.status_code == 200
    fb_data = fb_resp.json()
    assert fb_data["status"] == "confirmed"
    assert fb_data["triggered_replan"] is True
