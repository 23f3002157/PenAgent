"""Operator-owned policy. Nothing supplied by an LLM can extend this policy."""
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from penagent_common.models import StrictModel


class Expectation(StrictModel):
    expected_behavior: str
    denied_statuses: list[int] = Field(default_factory=lambda: [401, 403])
    protected_fields: list[str] = Field(default_factory=list)
    # Paths into JSON, configured by an authorized operator, never a target/LLM.
    forbidden_values: dict[str, str | int | bool] = Field(default_factory=dict)
    signal_fields: list[str] = Field(default_factory=list)
    requires_anonymous: bool = True
    owasp_categories: list[str] = Field(default_factory=list)


class OperationPolicy(StrictModel):
    method: str
    path: str
    risk: Literal["safe", "reversible", "destructive"] = "safe"
    allowed_headers: list[str] = Field(default_factory=list)
    header_variations: dict[str, list[str]] = Field(default_factory=dict)
    response_credentials: list[str] = Field(default_factory=list)
    auth_context_variations: list[str] = Field(default_factory=list)
    expectation: Expectation | None = None


class TargetPolicy(StrictModel):
    base_url: str
    operations: dict[str, OperationPolicy]
    # Session references which may carry credentials to this exact origin.
    credential_refs: list[str] = Field(default_factory=list)

    @field_validator("base_url")
    @classmethod
    def validate_base(cls, value: str) -> str:
        from penagent_common.policy import origin
        origin(value)  # numeric IP origins eliminate DNS rebinding/TOCTOU
        from urllib.parse import urlsplit
        u = urlsplit(value)
        if u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("target base_url must be an origin")
        return value.rstrip("/")


class Settings(StrictModel):
    targets: dict[str, TargetPolicy] = Field(default_factory=dict)
    sis_url: str = ""
    hgs_url: str = ""
    interpreter_url: str = ""
    service_token: str = ""
    api_tokens: dict[str, str] = Field(default_factory=dict)
    encryption_key: str = ""
    database: str = "execution.db"
    connect_timeout: float = Field(default=2, gt=0, le=60)
    read_timeout: float = Field(default=5, gt=0, le=120)
    service_timeout: float = Field(default=10, gt=0, le=120)
    request_timeout: float = Field(default=15, gt=0, le=300)
    max_response_size: int = Field(default=262144, ge=1, le=10000000)
    max_request_size: int = Field(default=65536, ge=1, le=1000000)
    max_probes: int = Field(default=30, ge=1, le=10000)
    max_mutations: int = Field(default=3, ge=0, le=100)
    max_depth: int = Field(default=6, ge=1, le=100)
    max_llm_calls: int = Field(default=4, ge=0, le=100)
    max_duration: float = Field(default=300, gt=0, le=86400)
    concurrency: int = Field(default=2, ge=1, le=50)
    requests_per_second: float = Field(default=2, gt=0, le=100)
    retries: int = Field(default=1, ge=0, le=3)
    llm_url: str = ""
    llm_model: str = ""
    llm_key: str = ""
    llm_provider: Literal["none", "gemini", "function_calling"] = "none"
    gemini_key: str = Field(default="", repr=False)
    llm_timeout: float = Field(default=20, gt=0, le=120)
    llm_retries: int = Field(default=1, ge=0, le=3)
    llm_max_tokens: int = Field(default=768, ge=128, le=4096)

    @classmethod
    def from_env(cls) -> "Settings":
        from dotenv import load_dotenv
        load_dotenv(os.environ.get("PENAGENT_ENV_FILE", ".env"), override=False)
        config = json.loads(Path(os.environ["PENAGENT_CONFIG"]).read_text(encoding="utf-8"))
        config.update({k: os.environ.get(env, config.get(k, "")) for k, env in {
            "sis_url": "SIS_URL", "hgs_url": "HGS_URL", "interpreter_url": "INTERPRETER_URL",
            "service_token": "PENAGENT_SERVICE_TOKEN", "encryption_key": "PENAGENT_STATE_KEY",
            "llm_key": "PENAGENT_LLM_KEY"}.items()})
        if os.environ.get("PENAGENT_API_TOKENS"):
            config["api_tokens"] = json.loads(os.environ["PENAGENT_API_TOKENS"])
        config["gemini_key"] = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY") or ""
        config["llm_provider"] = os.environ.get("PENAGENT_LLM_PROVIDER") or config.get("llm_provider", "none")
        if os.environ.get("GEMINI_MODEL"):
            config["llm_model"] = os.environ["GEMINI_MODEL"]
        return cls.model_validate(config)
