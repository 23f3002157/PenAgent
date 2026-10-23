from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sis.config import settings
from sis.api import router as v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    print(f"[*] Starting {settings.app_name} v{settings.version} on port {settings.port}")
    yield
    # Shutdown actions
    print(f"[*] Stopping {settings.app_name}")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Component 1 of PenAgent Pipeline: Spec Ingestion & Endpoint Graph Microservice",
    lifespan=lifespan,
)

# Cross-origin middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 API endpoints
app.include_router(v1_router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Health status endpoint for Docker Compose and orchestrator health checks."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.version,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sis.main:app", host=settings.host, port=settings.port, reload=True)
