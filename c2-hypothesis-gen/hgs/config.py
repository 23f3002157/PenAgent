import os
from pathlib import Path
from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "PenAgent Hypothesis Generation Service (HGS)"
    version: str = "1.0.0"
    host: str = Field(default_factory=lambda: os.getenv("HGS_HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("HGS_PORT", "9002")))
    
    # Spec Ingestion Service URL
    sis_url: str = Field(default_factory=lambda: os.getenv("SIS_URL", "http://localhost:9001"))
    
    # Message Bus & Queue
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    database_url: str = Field(
        default_factory=lambda: os.getenv(
            "HGS_DATABASE_URL", 
            os.getenv("DATABASE_URL", "sqlite:///./hgs.db")
        )
    )
    
    # LLM Settings
    anthropic_api_key: str = Field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = Field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"))
    openai_api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = Field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o"))
    
    # Planning & Pruning Budgets
    max_hypotheses_per_category: int = 4
    context_node_budget: int = 30
    
    # Base workspace path
    base_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("BASE_DIR", str(Path(__file__).resolve().parent.parent.parent.parent)))
    )


settings = Settings()
