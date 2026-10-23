from hgs.validator import HypothesisValidator
from hgs.models import AttackHypothesis, AttackSequenceStep


def test_hypothesis_validator(sample_attack_surface):
    nodes = sample_attack_surface["nodes"]

    # 1. Valid hypothesis
    valid_hyp = AttackHypothesis(
        id="hyp_valid",
        target_endpoints=["op_users_get_profile"],
        owasp_category="API1:BOLA",
        attack_sequence=[
            AttackSequenceStep(step=1, op="op_users_get_profile", notes="Valid step")
        ],
        impact_score=0.8,
        likelihood_score=0.7,
        priority=0.56,
    )

    # 2. Hallucinated endpoint hypothesis
    hallucinated_hyp = AttackHypothesis(
        id="hyp_fake",
        target_endpoints=["op_fictional_endpoint_does_not_exist"],
        owasp_category="API1:BOLA",
        attack_sequence=[
            AttackSequenceStep(step=1, op="op_fictional_endpoint_does_not_exist", notes="Fake step")
        ],
        impact_score=0.8,
        likelihood_score=0.7,
        priority=0.56,
    )

    # 3. Destructive action hypothesis
    destructive_hyp = AttackHypothesis(
        id="hyp_destructive",
        target_endpoints=["op_admin_delete_purge_cache"],
        owasp_category="API5:BFLA",
        attack_sequence=[
            AttackSequenceStep(step=1, op="op_admin_delete_purge_cache", notes="Delete cache")
        ],
        impact_score=0.8,
        likelihood_score=0.7,
        priority=0.56,
    )

    accepted, rejected = HypothesisValidator.validate_batch(
        [valid_hyp, hallucinated_hyp, destructive_hyp], nodes
    )

    assert len(accepted) == 2
    assert len(rejected) == 1
    assert rejected[0]["hypothesis_id"] == "hyp_fake"

    # Verify destructive action flagged
    dest_accepted = next(h for h in accepted if h.id == "hyp_destructive")
    assert dest_accepted.requires_approval is True

    valid_accepted = next(h for h in accepted if h.id == "hyp_valid")
    assert valid_accepted.requires_approval is False
