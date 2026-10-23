from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class HypothesisStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"
    CONFIRMED = "confirmed"


class Provenance(str, Enum):
    INITIAL_PLAN = "initial_plan"
    REPLAN = "replan"
    FEEDBACK = "feedback"


class AttackSequenceStep(BaseModel):
    model_config = ConfigDict(extra="ignore")
    step: int
    op: str  # Operation node ID
    method: Optional[str] = "GET"
    path: Optional[str] = ""
    notes: str = ""
    payload_hint: Dict[str, Any] = Field(default_factory=dict)


class AttackHypothesis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    target_endpoints: List[str] = Field(default_factory=list)
    owasp_category: str  # e.g., "API1:BOLA", "API2:Broken_Auth", "API5:BFLA"
    attack_sequence: List[AttackSequenceStep] = Field(default_factory=list)
    initial_payload: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    impact_score: float = Field(default=0.5, ge=0.0, le=1.0)
    likelihood_score: float = Field(default=0.5, ge=0.0, le=1.0)
    priority: float = Field(default=0.25, ge=0.0, le=1.0)
    status: HypothesisStatus = HypothesisStatus.PENDING
    requires_approval: bool = False
    provenance: Provenance = Provenance.INITIAL_PLAN
    created_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GenerateHypothesesRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: str
    graph_id: Optional[str] = None
    mode: str = "initial"  # "initial" | "replan"
    knowledge_state_delta: Dict[str, Any] = Field(default_factory=dict)
    prior_findings: List[Dict[str, Any]] = Field(default_factory=list)
    max_hypotheses: int = 20


class HypothesisBatch(BaseModel):
    model_config = ConfigDict(extra="ignore")
    batch_id: str
    target_id: str
    mode: str
    count: int
    hypotheses: List[AttackHypothesis] = Field(default_factory=list)
    created_at: str


class HypothesisFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    outcome: str  # confirmed_vulnerability, strong_signal, weak_signal, negative, error_crash
    status_code: Optional[int] = None
    evidence: Optional[str] = None
    discovered_state: Dict[str, Any] = Field(default_factory=dict)


class FeedbackResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hypothesis_id: str
    status: str
    score_updated: bool
    triggered_replan: bool


class ReplanEventRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: str
    finding_id: str
    owasp_category: str
    knowledge_delta: Dict[str, Any] = Field(default_factory=dict)
