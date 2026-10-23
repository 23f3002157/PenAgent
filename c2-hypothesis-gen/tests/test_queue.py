from hgs.models import AttackHypothesis, HypothesisStatus


def test_priority_queue(temp_queue):
    h_low = AttackHypothesis(
        id="hyp_low",
        target_endpoints=["op_low"],
        owasp_category="API8:Security_Misconfiguration",
        priority=0.35,
        status=HypothesisStatus.PENDING,
    )
    h_high = AttackHypothesis(
        id="hyp_high",
        target_endpoints=["op_high"],
        owasp_category="API1:BOLA",
        priority=0.85,
        status=HypothesisStatus.PENDING,
    )
    h_mid = AttackHypothesis(
        id="hyp_mid",
        target_endpoints=["op_mid"],
        owasp_category="API5:BFLA",
        priority=0.65,
        status=HypothesisStatus.PENDING,
    )

    temp_queue.push_batch("target_1", "batch_1", "initial", [h_low, h_high, h_mid])

    # Pop 1: should be h_high
    popped_1 = temp_queue.pop_next("target_1")
    assert popped_1 is not None
    assert popped_1.id == "hyp_high"
    assert popped_1.status == HypothesisStatus.IN_PROGRESS

    # Pop 2: should be h_mid
    popped_2 = temp_queue.pop_next("target_1")
    assert popped_2 is not None
    assert popped_2.id == "hyp_mid"

    # Pop 3: should be h_low
    popped_3 = temp_queue.pop_next("target_1")
    assert popped_3 is not None
    assert popped_3.id == "hyp_low"

    # Pop 4: empty
    assert temp_queue.pop_next("target_1") is None
