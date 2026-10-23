from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class JobStatus(str, Enum):
    QUEUED = "queued"
    PARSING = "parsing"
    BUILDING_GRAPH = "building_graph"
    TAGGING = "tagging"
    DONE = "done"
    FAILED = "failed"


class AuthInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    type: str = "none"  # "bearer", "api_key", "basic", "oauth2", "none"
    scopes: List[str] = Field(default_factory=list)
    header_name: Optional[str] = None
    location: Optional[str] = "header"
    description: Optional[str] = None


class ParameterModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    name: str
    location: str = Field(alias="in", default="query")  # path, query, header, cookie
    required: bool = False
    schema_type: Optional[str] = "string"
    schema_raw: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = ""


class EndpointNode(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    method: str
    path: str
    summary: Optional[str] = ""
    description: Optional[str] = ""
    parameters: List[ParameterModel] = Field(default_factory=list)
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schemas: Dict[str, Any] = Field(default_factory=dict)
    auth: AuthInfo = Field(default_factory=AuthInfo)
    attack_surface_tags: List[str] = Field(default_factory=list)
    service_prefix: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EndpointEdge(BaseModel):
    model_config = ConfigDict(extra="ignore")
    from_node: str
    to_node: str
    relation: str  # produces_param_consumed_by, shared_schema_field, openapi_link
    field: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EndpointGraph(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: str
    graph_id: str
    spec_hash: str
    nodes: List[EndpointNode] = Field(default_factory=list)
    edges: List[EndpointEdge] = Field(default_factory=list)
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackSurfaceView(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: str
    graph_id: str
    spec_hash: str
    nodes: List[EndpointNode] = Field(default_factory=list)
    edges: List[EndpointEdge] = Field(default_factory=list)
    tag_summary: Dict[str, int] = Field(default_factory=dict)
    total_nodes: int = 0
    total_edges: int = 0


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: str
    base_url: str
    spec_source: Optional[str] = None  # URL or file path or "auto"
    auth_profile: Optional[Dict[str, Any]] = None


class IngestJob(BaseModel):
    model_config = ConfigDict(extra="ignore")
    job_id: str
    target_id: str
    status: JobStatus = JobStatus.QUEUED
    error: Optional[str] = None
    graph_id: Optional[str] = None
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AugmentRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    method: str
    path: str
    parameters: Optional[List[Dict[str, Any]]] = None
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schemas: Optional[Dict[str, Any]] = None
    auth: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class RefreshResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: str
    drift_detected: bool
    old_hash: str
    new_hash: str
    nodes_count: int
    edges_count: int
    changes: Dict[str, Any] = Field(default_factory=dict)
