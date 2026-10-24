from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator
from hgs.models import AttackHypothesis
from sis.models import EndpointGraph


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Category(str, Enum):
    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"
    STRONG_SIGNAL = "STRONG_SIGNAL"
    WEAK_SIGNAL = "WEAK_SIGNAL"
    NEGATIVE = "NEGATIVE"
    ERROR_CRASH = "ERROR_CRASH"


class Binding(StrictModel):
    path: dict[str, JsonValue] = Field(default_factory=dict)
    query: dict[str, JsonValue] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = None
    body_type: Literal["json", "text", "form"] = "json"
    session_ref: str | None = None
    depends_on: list[int] = Field(default_factory=list)


class Probe(StrictModel):
    hypothesis_id: str
    op: str
    binding: Binding = Field(default_factory=Binding)
    parent_probe_id: str | None = None
    depth: int = Field(default=0, ge=0)
    motivation: str = "initial hypothesis"


class HTTPArguments(StrictModel):
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    url: str = Field(max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = None
    body_type: Literal["json", "text", "form"] = "json"
    params: dict[str, JsonValue] = Field(default_factory=dict)
    session_ref: str | None = None

    @field_validator("headers")
    @classmethod
    def clean_headers(cls, value: dict[str, str]) -> dict[str, str]:
        import re
        for k, v in value.items():
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", k) or any(ord(c) < 32 or ord(c) > 126 for c in v):
                raise ValueError("invalid header")
            if k.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "authorization", "cookie", "x-correlation-id"}:
                raise ValueError("reserved header; credentials require approved session reference")
        return value


class Parsed(StrictModel):
    kind: Literal["json", "text", "empty", "malformed", "binary"]
    data: JsonValue = None
    parse_error: str | None = None
    artifacts: dict[str, JsonValue] = Field(default_factory=dict)
    credential_fields: list[str] = Field(default_factory=list)
    body_sha256: str


class ExecutionResult(StrictModel):
    audit_id: str
    hypothesis_id: str
    probe_id: str = Field(default_factory=lambda: uuid4().hex)
    correlation_id: str
    op: str
    status: Literal["executed", "blocked", "error", "cancelled", "budget_exhausted", "duplicate"]
    status_code: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    parsed: Parsed | None = None
    latency_ms: float = 0.0
    attempts: int = 0
    error: str | None = None
    approval_required: bool = False
    risk_classification: Literal["safe", "reversible", "destructive", "unresolved"] = "unresolved"
    state_changes: list[str] = Field(default_factory=list)
    request_fingerprint: str | None = None


class Interpretation(StrictModel):
    audit_id: str
    hypothesis_id: str
    probe_id: str
    classification: Category
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str]
    observed_behavior: str
    expected_behavior: str
    reasoning_summary: str
    state_changes: list[str] = Field(default_factory=list)
    next_action: Literal["mutate", "replan", "preserve", "next_hypothesis", "stop"]
    replan_justified: bool = False
    human_approval_required: bool = False
    error: str | None = None
    model_assessment: dict[str, JsonValue] | None = None

    @field_validator("classification", mode="before")
    @classmethod
    def category_from_wire(cls, value):
        # Strict enums must still round-trip through HTTP/SQLite JSON.
        return Category(value)


class InterpretationInput(StrictModel):
    owner: str
    result: ExecutionResult
    hypothesis: AttackHypothesis
    probe: Probe


class Mutation(StrictModel):
    original_hypothesis_id: str
    observation_id: str
    change: str
    probe: Probe


class MutationInput(StrictModel):
    owner: str
    interpretation: Interpretation
    probe: Probe


class ExecuteInput(StrictModel):
    hypothesis: AttackHypothesis
    probe: Probe


class AuditCreate(StrictModel):
    audit_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    acknowledged_authorization: Literal[True]


class StateWrite(StrictModel):
    key: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,160}$")
    category: Literal["tokens", "cookies", "object_ids", "observations"]
    value: JsonValue


class SessionState(StrictModel):
    audit_id: str
    values: dict[str, dict[str, JsonValue]]


class Empty(StrictModel):
    pass


class ParseArguments(StrictModel):
    probe_id: str


class RunInput(StrictModel):
    bindings: dict[str, Binding] = Field(default_factory=dict)


class UpstreamGraph(BaseModel):
    """Use existing public models; do not fork or rename their fields."""
    graph: EndpointGraph
