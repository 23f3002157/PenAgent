import uuid
import datetime
import logging
from typing import Dict, Any, List, Optional

from hgs.models import (
    GenerateHypothesesRequest,
    HypothesisBatch,
    AttackHypothesis,
    HypothesisStatus,
    HypothesisFeedbackRequest,
    FeedbackResponse,
    ReplanEventRequest,
)
from hgs.surfacer import CandidateSurfacer
from hgs.planner import Planner
from hgs.validator import HypothesisValidator
from hgs.scorer import HypothesisScorer
from hgs.queue import PriorityQueue
from hgs.replan import ReplanHandler

logger = logging.getLogger(__name__)


class HypothesisGenerationService:
    """
    Main service coordinating attack surface retrieval, candidate bucketing,
    LLM/heuristic hypothesis generation, hallucination validation, scoring,
    queue writing, and dynamic replanning.
    """

    def __init__(
        self,
        queue: Optional[PriorityQueue] = None,
        surfacer: Optional[CandidateSurfacer] = None,
        planner: Optional[Planner] = None,
    ):
        self.queue = queue or PriorityQueue()
        self.surfacer = surfacer or CandidateSurfacer()
        self.planner = planner or Planner()
        # In-memory target knowledge cache
        self._target_knowledge: Dict[str, Dict[str, Any]] = {}
        # In-memory cached attack surfaces
        self._cached_attack_surfaces: Dict[str, Dict[str, Any]] = {}

    def set_cached_attack_surface(self, target_id: str, attack_surface: Dict[str, Any]) -> None:
        """Allows injecting or mocking attack surface for tests/offline runs."""
        self._cached_attack_surfaces[target_id] = attack_surface

    async def get_attack_surface(self, target_id: str) -> Dict[str, Any]:
        """Retrieves attack surface from local cache or SIS REST API."""
        if target_id in self._cached_attack_surfaces:
            return self._cached_attack_surfaces[target_id]

        surface = await self.surfacer.fetch_attack_surface(target_id)
        if surface:
            self._cached_attack_surfaces[target_id] = surface
            return surface

        return {}

    async def generate_hypotheses(self, request: GenerateHypothesesRequest) -> HypothesisBatch:
        """Full hypothesis generation pipeline."""
        target_id = request.target_id
        batch_id = f"batch_{uuid.uuid4().hex[:10]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Retrieve attack surface
        attack_surface = await self.get_attack_surface(target_id)
        if not attack_surface or not attack_surface.get("nodes"):
            logger.warning(f"No attack surface found for target {target_id}")
            return HypothesisBatch(
                batch_id=batch_id,
                target_id=target_id,
                mode=request.mode,
                count=0,
                hypotheses=[],
                created_at=now,
            )

        # Update target knowledge state
        knowledge = self._target_knowledge.setdefault(target_id, {})
        knowledge.update(request.knowledge_state_delta)

        # 2. Candidate Surfacer: bucket nodes by OWASP category
        candidates = self.surfacer.surface_candidates(attack_surface)

        # 3. Planner: Call LLM (or deterministic heuristic fallback)
        raw_hypotheses = await self.planner.generate_hypotheses(
            target_id=target_id,
            attack_surface=attack_surface,
            candidates=candidates,
            mode=request.mode,
            knowledge_state=knowledge,
            prior_findings=request.prior_findings,
            max_hypotheses=request.max_hypotheses,
        )

        # Tag batch_id
        for h in raw_hypotheses:
            h.metadata["batch_id"] = batch_id
            h.created_at = now

        # 4. Hypothesis Validator: Hallucination Guard
        valid_nodes = attack_surface.get("nodes", [])
        accepted_hypotheses, rejected = HypothesisValidator.validate_batch(raw_hypotheses, valid_nodes)
        if rejected:
            logger.warning(f"Rejected {len(rejected)} hallucinated hypotheses for target {target_id}")

        # 5. Impact × Likelihood Scorer
        edges = attack_surface.get("edges", [])
        scored_hypotheses = [
            HypothesisScorer.score_hypothesis(h, valid_nodes, edges) for h in accepted_hypotheses
        ]

        # 6. Dedup & Diversity Filter
        ranked_hypotheses = HypothesisScorer.filter_and_rank(
            scored_hypotheses, total_limit=request.max_hypotheses
        )

        # 7. Queue Writer: Persist and enqueue
        if request.mode == "replan":
            existing = self.queue.peek_queue(target_id, limit=50)
            merged = ReplanHandler.merge_replan_batch(existing, ranked_hypotheses, request.knowledge_state_delta)
            self.queue.push_batch(target_id, batch_id, request.mode, merged)
            ranked_hypotheses = merged
        else:
            self.queue.push_batch(target_id, batch_id, request.mode, ranked_hypotheses)

        return HypothesisBatch(
            batch_id=batch_id,
            target_id=target_id,
            mode=request.mode,
            count=len(ranked_hypotheses),
            hypotheses=ranked_hypotheses,
            created_at=now,
        )

    def get_batch(self, batch_id: str) -> Optional[HypothesisBatch]:
        """Retrieves stored batch by ID."""
        hypotheses = self.queue.get_batch(batch_id)
        if not hypotheses:
            return None
        target_id = hypotheses[0].target_endpoints[0] if hypotheses[0].target_endpoints else "unknown"
        return HypothesisBatch(
            batch_id=batch_id,
            target_id=target_id,
            mode="stored",
            count=len(hypotheses),
            hypotheses=hypotheses,
            created_at=hypotheses[0].created_at or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    async def handle_feedback(self, hypothesis_id: str, request: HypothesisFeedbackRequest) -> FeedbackResponse:
        """Processes execution outcome from Executor/Interpreter to update scoring and trigger replanning."""
        hyp = self.queue.get_hypothesis(hypothesis_id)
        if not hyp:
            return FeedbackResponse(
                hypothesis_id=hypothesis_id,
                status="not_found",
                score_updated=False,
                triggered_replan=False,
            )

        triggered_replan = False
        outcome = request.outcome.lower()

        if outcome == "confirmed_vulnerability":
            hyp.status = HypothesisStatus.CONFIRMED
            hyp.priority = 1.0
            triggered_replan = True
        elif outcome == "strong_signal":
            hyp.status = HypothesisStatus.IN_PROGRESS
            hyp.priority = min(1.0, round(hyp.priority * 1.3, 3))
            triggered_replan = True
        elif outcome == "negative":
            hyp.status = HypothesisStatus.DONE
            hyp.priority = 0.0
        elif outcome == "error_crash":
            hyp.status = HypothesisStatus.FAILED
            hyp.priority = 0.1
        else:
            hyp.status = HypothesisStatus.DONE

        hyp.metadata["last_feedback"] = request.model_dump()
        self.queue.update_hypothesis(hyp)

        # If significant finding was confirmed, trigger replan
        if triggered_replan and request.discovered_state:
            target_id = hyp.metadata.get("target_id") or (
                hyp.target_endpoints[0].split("_")[1] if "_" in hyp.target_endpoints[0] else "default"
            )
            replan_req = GenerateHypothesesRequest(
                target_id=target_id,
                mode="replan",
                knowledge_state_delta=request.discovered_state,
                prior_findings=[{"hypothesis_id": hypothesis_id, "evidence": request.evidence}],
            )
            await self.generate_hypotheses(replan_req)

        return FeedbackResponse(
            hypothesis_id=hypothesis_id,
            status=hyp.status.value,
            score_updated=True,
            triggered_replan=triggered_replan,
        )

    def pop_next(self, target_id: str) -> Optional[AttackHypothesis]:
        """Pops next pending hypothesis for Executor."""
        return self.queue.pop_next(target_id)

    def peek_queue(self, target_id: str, limit: int = 25) -> List[AttackHypothesis]:
        return self.queue.peek_queue(target_id, limit=limit)
