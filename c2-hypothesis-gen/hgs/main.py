from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hgs.config import settings
from hgs.api import router as v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[*] Starting {settings.app_name} v{settings.version} on port {settings.port}")
    yield
    print(f"[*] Stopping {settings.app_name}")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Component 2 of PenAgent Pipeline: Attack Hypothesis Generation Service (HGS)",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1_router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for Docker Compose and orchestrator."""
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.version,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hgs.main:app", host=settings.host, port=settings.port, reload=True)
