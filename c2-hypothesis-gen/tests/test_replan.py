from hgs.replan import ReplanHandler
from hgs.models import AttackHypothesis, HypothesisStatus, Provenance


def test_replan_merge_and_boost():
    # Existing queue: 1 completed, 1 pending vault hypothesis
    h_done = AttackHypothesis(
        id="hyp_auth",
        target_endpoints=["op_auth"],
        owasp_category="API2:Broken_Auth",
        status=HypothesisStatus.CONFIRMED,
        priority=0.9,
    )
    h_pending_vault = AttackHypothesis(
        id="hyp_vault",
        target_endpoints=["op_vault"],
        owasp_category="API1:BOLA",
        status=HypothesisStatus.PENDING,
        priority=0.50,
        rationale="Probe vault documents using leaked doc_id",
    )

    # New replanned hypothesis targeting newly exposed tenant
    h_new_tenant = AttackHypothesis(
        id="hyp_tenant",
        target_endpoints=["op_tenant"],
        owasp_category="API1:BOLA",
        status=HypothesisStatus.PENDING,
        priority=0.55,
        rationale="Access tenant profile",
        initial_payload={"doc_id": "doc_102"},
    )

    existing = [h_done, h_pending_vault]
    new_batch = [h_new_tenant]

    knowledge_delta = {"doc_id": "doc_102", "service_token": "tok_xyz"}
    merged = ReplanHandler.merge_replan_batch(existing, new_batch, knowledge_delta)

    # h_done must still be present and confirmed
    done_item = next(h for h in merged if h.id == "hyp_auth")
    assert done_item.status == HypothesisStatus.CONFIRMED

    # h_pending_vault should be boosted because its rationale mentions doc_id
    vault_item = next(h for h in merged if h.id == "hyp_vault")
    assert vault_item.priority > 0.50
    assert vault_item.metadata.get("replan_boosted") is True

    # h_new_tenant should be merged and boosted
    tenant_item = next(h for h in merged if h.id == "hyp_tenant")
    assert tenant_item.provenance == Provenance.REPLAN
    assert tenant_item.priority > 0.55
