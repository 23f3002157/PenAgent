from typing import List, Optional
from fastapi import APIRouter, HTTPException, status, Response

from hgs.models import (
    GenerateHypothesesRequest,
    HypothesisBatch,
    AttackHypothesis,
    HypothesisFeedbackRequest,
    FeedbackResponse,
    ReplanEventRequest,
)
from hgs.service import HypothesisGenerationService

router = APIRouter(prefix="/v1", tags=["Hypothesis Generation"])
service = HypothesisGenerationService()


@router.post("/hypotheses/generate", response_model=HypothesisBatch, status_code=status.HTTP_200_OK)
async def generate_hypotheses(request: GenerateHypothesesRequest):
    """
    Generates a ranked, validated queue of attack hypotheses for the given target API surface.
    Used for both INITIAL planning and dynamic REPLANNING.
    """
    try:
        batch = await service.generate_hypotheses(request)
        return batch
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hypothesis generation failed: {str(e)}",
        )


@router.get("/hypotheses/{batch_id}", response_model=HypothesisBatch)
async def get_hypothesis_batch(batch_id: str):
    """Retrieves a previously generated hypothesis batch."""
    batch = service.get_batch(batch_id)
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hypothesis batch '{batch_id}' not found",
        )
    return batch


@router.post("/hypotheses/{hypothesis_id}/feedback", response_model=FeedbackResponse)
async def report_hypothesis_feedback(hypothesis_id: str, request: HypothesisFeedbackRequest):
    """
    Executor/Interpreter reports execution outcome.
    Updates hypothesis status, score priors, and triggers replanning on significant findings.
    """
    resp = await service.handle_feedback(hypothesis_id, request)
    if resp.status == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Hypothesis '{hypothesis_id}' not found",
        )
    return resp


@router.get("/queue/{target_id}/next", response_model=Optional[AttackHypothesis])
async def pop_next_hypothesis(target_id: str, response: Response):
    """
    Pops the next highest-priority pending hypothesis for Component 3 (Executor) to probe.
    Returns 204 No Content if queue is empty.
    """
    next_hyp = service.pop_next(target_id)
    if not next_hyp:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    return next_hyp


@router.get("/queue/{target_id}", response_model=List[AttackHypothesis])
async def peek_queue(target_id: str, limit: int = 25):
    """Peeks at the current prioritized queue of pending hypotheses for a target."""
    return service.peek_queue(target_id, limit=limit)


@router.post("/events/replan", response_model=HypothesisBatch)
async def trigger_replan_event(request: ReplanEventRequest):
    """Triggered by finding.significant event to initiate dynamic replanning."""
    replan_req = GenerateHypothesesRequest(
        target_id=request.target_id,
        mode="replan",
        knowledge_state_delta=request.knowledge_delta,
        prior_findings=[{"finding_id": request.finding_id, "category": request.owasp_category}],
    )
    return await service.generate_hypotheses(replan_req)
