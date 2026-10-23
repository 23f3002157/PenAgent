import uuid
import datetime
import logging
from typing import Dict, Any, Optional, List, Tuple
from collections import Counter

from sis.models import (
    IngestRequest,
    IngestJob,
    JobStatus,
    EndpointGraph,
    EndpointNode,
    EndpointEdge,
    AttackSurfaceView,
    AugmentRequest,
    RefreshResponse,
    ParameterModel,
    AuthInfo,
)
from sis.adapters import get_adapter
from sis.normalizer import SpecNormalizer
from sis.graph_builder import GraphBuilder
from sis.tagger import AttackSurfaceTagger
from sis.storage import GraphStorage
from sis.events import event_bus

logger = logging.getLogger(__name__)


class SpecIngestionService:
    """
    Core service coordinating spec loading, normalization, graph generation,
    attack surface tagging, storage persistence, and augmentation.
    """

    def __init__(self, storage: Optional[GraphStorage] = None):
        self.storage = storage or GraphStorage()
        self.normalizer = SpecNormalizer()

    async def create_ingest_job(self, request: IngestRequest) -> IngestJob:
        """Initializes and persists a new ingestion job."""
        job_id = f"job_{uuid.uuid4().hex[:12]}"
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        job = IngestJob(
            job_id=job_id,
            target_id=request.target_id,
            status=JobStatus.QUEUED,
            created_at=now,
            updated_at=now,
            metadata={
                "base_url": request.base_url,
                "spec_source": request.spec_source,
                "auth_profile": request.auth_profile,
            },
        )
        self.storage.save_job(job)
        return job

    async def run_ingestion_pipeline(self, job_id: str) -> EndpointGraph:
        """Executes the full ingestion pipeline for an existing job."""
        job = self.storage.get_job(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        target_id = job.target_id
        meta = job.metadata
        base_url = meta.get("base_url", "")
        spec_source = meta.get("spec_source")

        try:
            # 1. Parsing Phase
            job.status = JobStatus.PARSING
            self.storage.save_job(job)

            adapter = get_adapter(target_id, spec_source)
            raw_spec, adapter_metadata = await adapter.load_spec(target_id, base_url, spec_source)

            normalized_spec, spec_hash = self.normalizer.normalize(raw_spec)

            # 2. Building Graph Phase
            job.status = JobStatus.BUILDING_GRAPH
            self.storage.save_job(job)

            builder = GraphBuilder()
            
            # 3. Tagging Phase
            job.status = JobStatus.TAGGING
            self.storage.save_job(job)

            graph = builder.build_graph(target_id, spec_hash, normalized_spec, adapter_metadata)

            # Persist graph, spec revision, and complete job
            self.storage.save_graph(graph)
            self.storage.record_spec_revision(target_id, spec_hash, raw_spec)

            job.status = JobStatus.DONE
            job.graph_id = graph.graph_id
            job.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.storage.save_job(job)

            # Publish event
            await event_bus.emit_graph_ready(
                target_id=target_id,
                graph_id=graph.graph_id,
                nodes_count=len(graph.nodes),
                edges_count=len(graph.edges),
            )

            return graph

        except Exception as e:
            logger.exception(f"Ingestion failed for job {job_id}: {e}")
            job.status = JobStatus.FAILED
            job.error = str(e)
            job.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.storage.save_job(job)
            raise

    def get_graph(self, target_id: str) -> Optional[EndpointGraph]:
        """Retrieves stored EndpointGraph."""
        return self.storage.get_graph(target_id)

    def get_attack_surface(self, target_id: str) -> Optional[AttackSurfaceView]:
        """
        Returns pruned, tag-annotated view of the graph consumed by HGS.
        Includes nodes with attack-surface tags and connected edges.
        """
        graph = self.storage.get_graph(target_id)
        if not graph:
            return None

        # Filter nodes that have at least one attack surface tag
        tagged_nodes = [n for n in graph.nodes if len(n.attack_surface_tags) > 0]
        tagged_node_ids = {n.id for n in tagged_nodes}

        # Include edges connecting tagged nodes
        relevant_edges = [
            e for e in graph.edges if e.from_node in tagged_node_ids or e.to_node in tagged_node_ids
        ]

        # Summarize tag occurrences
        all_tags = [t for n in tagged_nodes for t in n.attack_surface_tags]
        tag_summary = dict(Counter(all_tags))

        return AttackSurfaceView(
            target_id=graph.target_id,
            graph_id=graph.graph_id,
            spec_hash=graph.spec_hash,
            nodes=tagged_nodes,
            edges=relevant_edges,
            tag_summary=tag_summary,
            total_nodes=len(tagged_nodes),
            total_edges=len(relevant_edges),
        )

    async def augment_graph(self, target_id: str, request: AugmentRequest) -> EndpointGraph:
        """
        Merges an undocumented endpoint discovered by live executor probing into the stored graph.
        Re-tags and re-infers edges.
        """
        graph = self.storage.get_graph(target_id)
        if not graph:
            raise ValueError(f"No existing graph found for target {target_id}")

        method_upper = request.method.upper()
        clean_path = request.path

        builder = GraphBuilder()
        new_op_id = builder.generate_operation_id(method_upper, clean_path)

        # Convert parameters
        params: List[ParameterModel] = []
        if request.parameters:
            for p in request.parameters:
                params.append(
                    ParameterModel(
                        name=p.get("name", "param"),
                        location=p.get("in", "query"),
                        required=p.get("required", False),
                        schema_type=p.get("schema", {}).get("type", "string") if isinstance(p.get("schema"), dict) else "string",
                        schema_raw=p.get("schema", {}) if isinstance(p.get("schema"), dict) else {},
                    )
                )

        service_prefix = builder.extract_service_prefix(clean_path)
        auth = AuthInfo(**request.auth) if request.auth else AuthInfo(type="none")

        new_node = EndpointNode(
            id=new_op_id,
            method=method_upper,
            path=clean_path,
            summary=f"Discovered endpoint: {method_upper} {clean_path}",
            parameters=params,
            request_body_schema=request.request_body_schema,
            response_schemas=request.response_schemas or {"200": {"description": "Discovered"}},
            auth=auth,
            attack_surface_tags=[],
            service_prefix=service_prefix,
            metadata={"augmented": True, **(request.metadata or {})},
        )

        # Remove existing if updating, otherwise append
        existing_nodes = [n for n in graph.nodes if n.id != new_op_id]
        existing_nodes.append(new_node)

        # Re-tag all nodes
        updated_nodes = AttackSurfaceTagger.tag_nodes(existing_nodes)

        # Re-infer edges
        mock_spec = {"paths": {}}
        updated_edges = builder.infer_edges(updated_nodes, mock_spec)

        graph.nodes = updated_nodes
        graph.edges = updated_edges
        graph.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        graph.metadata["last_augmented"] = new_op_id

        self.storage.save_graph(graph)
        return graph

    async def refresh_spec(
        self, target_id: str, base_url: str, spec_source: Optional[str] = None
    ) -> RefreshResponse:
        """
        Re-pulls target specification and diffs against stored SHA-256 hash.
        If drift is detected, updates graph and publishes graph.ready.
        """
        stored_hash = self.storage.get_stored_spec_hash(target_id)
        adapter = get_adapter(target_id, spec_source)
        raw_spec, adapter_metadata = await adapter.load_spec(target_id, base_url, spec_source)

        normalized_spec, new_hash = self.normalizer.normalize(raw_spec)

        if stored_hash == new_hash:
            graph = self.storage.get_graph(target_id)
            return RefreshResponse(
                target_id=target_id,
                drift_detected=False,
                old_hash=stored_hash or "",
                new_hash=new_hash,
                nodes_count=len(graph.nodes) if graph else 0,
                edges_count=len(graph.edges) if graph else 0,
                changes={"status": "No schema drift detected"},
            )

        # Drift detected: Rebuild graph
        builder = GraphBuilder()
        new_graph = builder.build_graph(target_id, new_hash, normalized_spec, adapter_metadata)
        self.storage.save_graph(new_graph)
        self.storage.record_spec_revision(target_id, new_hash, raw_spec)

        # Calculate diff changes
        old_graph = self.storage.get_graph(target_id)
        old_ops = {n.id for n in old_graph.nodes} if old_graph else set()
        new_ops = {n.id for n in new_graph.nodes}

        changes = {
            "added_operations": list(new_ops - old_ops),
            "removed_operations": list(old_ops - new_ops),
            "total_operations": len(new_ops),
        }

        # Emit graph.ready event
        await event_bus.emit_graph_ready(
            target_id=target_id,
            graph_id=new_graph.graph_id,
            nodes_count=len(new_graph.nodes),
            edges_count=len(new_graph.edges),
        )

        return RefreshResponse(
            target_id=target_id,
            drift_detected=True,
            old_hash=stored_hash or "none",
            new_hash=new_hash,
            nodes_count=len(new_graph.nodes),
            edges_count=len(new_graph.edges),
            changes=changes,
        )
