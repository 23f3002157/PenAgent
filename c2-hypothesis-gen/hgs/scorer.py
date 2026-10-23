from typing import List, Dict, Any, Set
from hgs.models import AttackHypothesis
from hgs.config import settings


class HypothesisScorer:
    """
    Computes Impact × Likelihood priority scores and applies category diversity caps
    and near-duplicate deduplication.
    """

    CATEGORY_CVSS_PRIORS = {
        "API1:BOLA": 0.82,
        "API2:Broken_Auth": 0.88,
        "API3:BOPLA": 0.72,
        "API5:BFLA": 0.80,
        "API8:Security_Misconfiguration": 0.65,
    }

    CATEGORY_PREVALENCE_PRIORS = {
        "API1:BOLA": 0.75,
        "API2:Broken_Auth": 0.65,
        "API3:BOPLA": 0.70,
        "API5:BFLA": 0.60,
        "API8:Security_Misconfiguration": 0.70,
    }

    @classmethod
    def score_hypothesis(
        cls,
        hyp: AttackHypothesis,
        valid_nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> AttackHypothesis:
        """Calculates refined impact, likelihood, and priority scores."""
        node_map = {n["id"]: n for n in valid_nodes if "id" in n}
        cat = hyp.owasp_category

        # 1. Base Impact
        base_impact = cls.CATEGORY_CVSS_PRIORS.get(cat, 0.70)
        
        # Sensitivity bonuses
        impact_bonus = 0.0
        for ep in hyp.target_endpoints:
            node = node_map.get(ep, {})
            tags = node.get("attack_surface_tags", [])
            if "sensitive_response" in tags:
                impact_bonus += 0.08
            if "admin_surface" in tags:
                impact_bonus += 0.10
        
        impact = min(1.0, max(0.1, base_impact + impact_bonus))

        # 2. Base Likelihood
        base_likelihood = cls.CATEGORY_PREVALENCE_PRIORS.get(cat, 0.60)
        likelihood_bonus = 0.0

        # Structural edge bonus: does sequence follow high-confidence or cross-service edges?
        edge_keys = {(e.get("from_node"), e.get("to_node")): e for e in edges}
        seq = hyp.attack_sequence
        for i in range(len(seq) - 1):
            pair = (seq[i].op, seq[i + 1].op)
            if pair in edge_keys:
                edge = edge_keys[pair]
                conf = edge.get("confidence", 0.5)
                is_cross = edge.get("metadata", {}).get("cross_service", False)
                likelihood_bonus += 0.10 * conf
                if is_cross:
                    likelihood_bonus += 0.12

        # Auth bonus: unauthenticated mutation
        for ep in hyp.target_endpoints:
            node = node_map.get(ep, {})
            if "unauthenticated_sensitive_action" in node.get("attack_surface_tags", []):
                likelihood_bonus += 0.15

        likelihood = min(1.0, max(0.1, base_likelihood + likelihood_bonus))

        hyp.impact_score = round(impact, 3)
        hyp.likelihood_score = round(likelihood, 3)
        hyp.priority = round(impact * likelihood, 3)
        return hyp

    @classmethod
    def filter_and_rank(
        cls,
        hypotheses: List[AttackHypothesis],
        max_per_category: int = settings.max_hypotheses_per_category,
        total_limit: int = 25,
    ) -> List[AttackHypothesis]:
        """
        Deduplicates near-identical attack sequences, enforces diversity caps per OWASP category,
        and ranks hypotheses descending by priority.
        """
        # Sort descending by priority
        hypotheses.sort(key=lambda h: h.priority, reverse=True)

        seen_signatures: Set[str] = set()
        category_counts: Dict[str, int] = {}
        filtered: List[AttackHypothesis] = []

        for hyp in hypotheses:
            # Dedup signature: category + target endpoints + steps
            step_ops = [s.op for s in hyp.attack_sequence]
            sig = f"{hyp.owasp_category}|{sorted(hyp.target_endpoints)}|{step_ops}"
            if sig in seen_signatures:
                continue

            cat = hyp.owasp_category
            count = category_counts.get(cat, 0)
            if count >= max_per_category:
                continue

            seen_signatures.add(sig)
            category_counts[cat] = count + 1
            filtered.append(hyp)

            if len(filtered) >= total_limit:
                break

        return filtered
