from hgs.scorer import HypothesisScorer
from hgs.models import AttackHypothesis, AttackSequenceStep


def test_scorer_structural_bonus(sample_attack_surface):
    nodes = sample_attack_surface["nodes"]
    edges = sample_attack_surface["edges"]

    # Hypothesis following cross-service edges: Auth -> User -> Vault
    chained_hyp = AttackHypothesis(
        id="hyp_chained",
        target_endpoints=["op_vault_get_document"],
        owasp_category="API1:BOLA",
        attack_sequence=[
            AttackSequenceStep(step=1, op="op_auth_post_exchange_token", notes="token"),
            AttackSequenceStep(step=2, op="op_users_get_profile", notes="user"),
            AttackSequenceStep(step=3, op="op_vault_get_document", notes="doc"),
        ],
    )

    scored = HypothesisScorer.score_hypothesis(chained_hyp, nodes, edges)
    # With structural edge bonus, likelihood should be high
    assert scored.likelihood_score >= 0.75
    assert scored.priority >= 0.60


def test_diversity_filter():
    # Create 6 hypotheses for API1:BOLA
    hyps = []
    for i in range(6):
        hyps.append(
            AttackHypothesis(
                id=f"hyp_{i}",
                target_endpoints=[f"op_target_{i}"],
                owasp_category="API1:BOLA",
                attack_sequence=[
                    AttackSequenceStep(step=1, op=f"op_target_{i}", notes="step")
                ],
                priority=0.5 + (i * 0.05),
            )
        )

    # Filter with cap of 3
    filtered = HypothesisScorer.filter_and_rank(hyps, max_per_category=3)
    assert len(filtered) == 3
    # Highest priorities kept
    assert filtered[0].id == "hyp_5"
    assert filtered[1].id == "hyp_4"
    assert filtered[2].id == "hyp_3"
