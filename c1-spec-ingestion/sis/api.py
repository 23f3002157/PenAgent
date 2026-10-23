from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, status
from pydantic import BaseModel

from sis.models import (
    IngestRequest,
    IngestJob,
    EndpointGraph,
    AttackSurfaceView,
    AugmentRequest,
    RefreshResponse,
)
from sis.service import SpecIngestionService

router = APIRouter(prefix="/v1", tags=["Spec Ingestion"])
service = SpecIngestionService()


class IngestJobResponse(BaseModel):
    job_id: str
    target_id: str
    status: str
    message: str


@router.post("/ingest", response_model=IngestJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_spec(request: IngestRequest, background_tasks: BackgroundTasks):
    """
    Asynchronously ingests, normalizes, and constructs the endpoint graph for a target.
    Returns job_id for status polling.
    """
    job = await service.create_ingest_job(request)
    # Schedule background ingestion
    background_tasks.add_task(service.run_ingestion_pipeline, job.job_id)

    return IngestJobResponse(
        job_id=job.job_id,
        target_id=job.target_id,
        status=job.status.value,
        message="Spec ingestion job queued successfully",
    )


@router.get("/ingest/{job_id}", response_model=IngestJob)
async def get_ingest_job_status(job_id: str):
    """Returns current status of an ingestion job (queued | parsing | building_graph | tagging | done | failed)."""
    job = service.storage.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Ingestion job '{job_id}' not found",
        )
    return job


@router.get("/graph/{target_id}", response_model=EndpointGraph)
async def get_endpoint_graph(target_id: str):
    """Retrieves full EndpointGraph (all operation nodes and inferred dependency edges)."""
    graph = service.get_graph(target_id)
    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"EndpointGraph for target '{target_id}' not found. Run /v1/ingest first.",
        )
    return graph


@router.get("/graph/{target_id}/attack-surface", response_model=AttackSurfaceView)
async def get_attack_surface(target_id: str):
    """
    Retrieves the pruned, tag-annotated attack surface view consumed by
    Component 2 (Hypothesis Generation Service).
    """
    attack_surface = service.get_attack_surface(target_id)
    if not attack_surface:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack surface view for target '{target_id}' not found.",
        )
    return attack_surface


@router.post("/graph/{target_id}/augment", response_model=EndpointGraph)
async def augment_endpoint(target_id: str, request: AugmentRequest):
    """
    Merges an undocumented endpoint discovered during live probing into the stored graph,
    updating security tags and dependency edges.
    """
    try:
        updated_graph = await service.augment_graph(target_id, request)
        return updated_graph
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


class RefreshRequest(BaseModel):
    base_url: str
    spec_source: Optional[str] = None


@router.post("/graph/{target_id}/refresh", response_model=RefreshResponse)
async def refresh_spec(target_id: str, request: RefreshRequest):
    """
    Re-pulls target specification and compares SHA-256 hash against stored version.
    Re-indexes graph if schema drift is detected.
    """
    try:
        result = await service.refresh_spec(target_id, request.base_url, request.spec_source)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Spec refresh failed: {str(e)}",
        )
