import logging
from typing import Dict, Any, Optional, Set
from hgs.models import AttackHypothesis, HypothesisStatus, Provenance

logger = logging.getLogger(__name__)


class ReplanHandler:
    """
    Handles replanning triggers caused by significant findings reported by the
    response interpreter. Merges follow-up hypotheses and re-ranks the queue.
    """

    @classmethod
    def merge_replan_batch(
        cls,
        existing_hypotheses: list[AttackHypothesis],
        new_batch: list[AttackHypothesis],
        knowledge_delta: Dict[str, Any],
    ) -> list[AttackHypothesis]:
        """
        Merges new replanned hypotheses into the queue while strictly preserving
        already executed/confirmed hypotheses.
        Promotes hypotheses that can consume newly leaked state tokens/IDs.
        """
        existing_by_id = {h.id: h for h in existing_hypotheses}
        existing_signatures: Set[str] = {
            f"{h.owasp_category}|{sorted(h.target_endpoints)}" for h in existing_hypotheses
        }

        # Identify newly discovered tokens / parameters in delta
        leaked_keys = set(knowledge_delta.keys())

        # 1. Update and boost existing pending hypotheses if they can use leaked keys
        for h in existing_hypotheses:
            if h.status == HypothesisStatus.PENDING:
                # If hypothesis targets an endpoint that matches leaked keys, boost priority
                rationale_lower = h.rationale.lower()
                if any(k.lower() in rationale_lower for k in leaked_keys):
                    h.priority = min(1.0, round(h.priority * 1.35, 3))
                    h.likelihood_score = min(1.0, round(h.likelihood_score * 1.25, 3))
                    h.provenance = Provenance.REPLAN
                    h.metadata["replan_boosted"] = True

        # 2. Add new hypotheses from replan batch that are not duplicates
        merged = list(existing_hypotheses)
        for new_hyp in new_batch:
            sig = f"{new_hyp.owasp_category}|{sorted(new_hyp.target_endpoints)}"
            if sig not in existing_signatures:
                new_hyp.provenance = Provenance.REPLAN
                new_hyp.metadata["replan_created"] = True
                # Boost if directly targeting leaked knowledge
                if any(k.lower() in str(new_hyp.initial_payload).lower() or k.lower() in new_hyp.rationale.lower() for k in leaked_keys):
                    new_hyp.priority = min(1.0, round(new_hyp.priority * 1.25, 3))
                merged.append(new_hyp)
                existing_signatures.add(sig)

        # 3. Re-sort so pending hypotheses with highest priority are at the front
        # Keep non-pending sorted at the end
        pending = [h for h in merged if h.status == HypothesisStatus.PENDING]
        non_pending = [h for h in merged if h.status != HypothesisStatus.PENDING]

        pending.sort(key=lambda h: h.priority, reverse=True)
        return pending + non_pending
