import os
from pathlib import Path
from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "PenAgent Spec Ingestion Service (SIS)"
    version: str = "1.0.0"
    host: str = Field(default_factory=lambda: os.getenv("SIS_HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("SIS_PORT", "9001")))
    
    # Storage & Persistence
    database_url: str = Field(
        default_factory=lambda: os.getenv(
            "POSTGRES_DSN", 
            os.getenv("DATABASE_URL", "sqlite:///./sis.db")
        )
    )
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    
    # Target Defaults
    juice_shop_url: str = Field(default_factory=lambda: os.getenv("JUICE_SHOP_URL", "http://localhost:18001"))
    juice_shop_spec: str = Field(default_factory=lambda: os.getenv("JUICE_SHOP_SPEC", "specs/juice_shop_sample.json"))
    
    srebench_url: str = Field(default_factory=lambda: os.getenv("SREBENCH_URL", "http://localhost:18002"))
    srebench_spec: str = Field(default_factory=lambda: os.getenv("SREBENCH_SPEC", "specs/srebench_openapi.json"))
    
    dvws_url: str = Field(default_factory=lambda: os.getenv("DVWS_URL", "http://localhost:18003"))
    dvws_spec: str = Field(default_factory=lambda: os.getenv("DVWS_SPEC", "specs/dvws_openapi.json"))
    
    # App base path (for resolving relative file specs)
    base_dir: Path = Field(default_factory=lambda: Path(os.getenv("BASE_DIR", str(Path(__file__).resolve().parent.parent.parent.parent))))


settings = Settings()
