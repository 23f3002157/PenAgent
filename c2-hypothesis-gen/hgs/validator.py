from typing import List, Dict, Any, Set, Tuple
from hgs.models import AttackHypothesis


class HypothesisValidator:
    """
    Hallucination Guard: Validates that every target endpoint and sequence step
    emitted by the planner exists in the actual ingested EndpointGraph.
    Also flags destructive actions requiring human-in-the-loop approval.
    """

    DESTRUCTIVE_KEYWORDS = {"delete", "purge", "drop", "reset", "destroy", "truncate", "kill"}

    @classmethod
    def validate_batch(
        cls, hypotheses: List[AttackHypothesis], valid_nodes: List[Dict[str, Any]]
    ) -> Tuple[List[AttackHypothesis], List[Dict[str, Any]]]:
        """
        Validates hypotheses against real graph nodes.
        Returns: (accepted_hypotheses, rejected_records)
        """
        valid_node_map = {n["id"]: n for n in valid_nodes if "id" in n}
        valid_ids: Set[str] = set(valid_node_map.keys())

        accepted: List[AttackHypothesis] = []
        rejected: List[Dict[str, Any]] = []

        for hyp in hypotheses:
            rejection_reasons = []

            # 1. Validate target endpoints
            if not hyp.target_endpoints:
                rejection_reasons.append("Missing target_endpoints")

            for ep in hyp.target_endpoints:
                if ep not in valid_ids:
                    rejection_reasons.append(f"Hallucinated target endpoint ID: '{ep}'")

            # 2. Validate attack sequence step ops
            for step in hyp.attack_sequence:
                if step.op not in valid_ids:
                    rejection_reasons.append(f"Hallucinated step op ID at step {step.step}: '{step.op}'")
                else:
                    # Enrich step with real method and path
                    real_node = valid_node_map[step.op]
                    step.method = real_node.get("method", "GET")
                    step.path = real_node.get("path", "")

            # 3. If any hallucinated nodes, reject
            if rejection_reasons:
                rejected.append({
                    "hypothesis_id": hyp.id,
                    "reasons": rejection_reasons,
                    "hypothesis": hyp.model_dump(),
                })
                continue

            # 4. Human gate evaluation: check for destructive actions
            is_destructive = False
            for step in hyp.attack_sequence:
                node_data = valid_node_map[step.op]
                method = node_data.get("method", "").upper()
                path = node_data.get("path", "").lower()
                summary = (node_data.get("summary") or "").lower()

                if method == "DELETE":
                    is_destructive = True
                    break
                for kw in cls.DESTRUCTIVE_KEYWORDS:
                    if kw in path or kw in summary:
                        is_destructive = True
                        break

            hyp.requires_approval = is_destructive
            accepted.append(hyp)

        return accepted, rejected
