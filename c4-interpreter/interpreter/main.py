from fastapi import Depends, FastAPI
from penagent_common.api import BodyLimit, install_errors, machine_dependency
from penagent_common.config import Settings
from penagent_common.models import StrictModel, Interpretation, Mutation
from penagent_common.store import Store
from interpreter.service import Interpreter


class EvidenceRequest(StrictModel):
    owner: str
    probe_id: str


def create_app(settings: Settings) -> FastAPI:
    if not settings.service_token:
        raise ValueError("PENAGENT_SERVICE_TOKEN is required")
    app = FastAPI(title="PenAgent Component 4: Response Interpreter", version="0.1.0")
    app.add_middleware(BodyLimit, limit=settings.max_request_size)
    store = Store(settings)
    service = Interpreter(settings, store)
    app.state.interpreter = service
    machine = machine_dependency(settings)
    install_errors(app)

    @app.get("/health")
    async def health():
        return {"status": "healthy", "component": 4}

    @app.get("/ready")
    async def ready():
        with store.connection() as db:
            db.execute("SELECT 1")
        return {"status": "ready"}

    @app.post("/v1/audits/{audit}/interpret", response_model=Interpretation)
    async def interpret(audit: str, request: EvidenceRequest, authorized=Depends(machine)):
        return await service.interpret(audit, request.owner, request.probe_id)

    @app.post("/v1/audits/{audit}/mutations", response_model=Mutation | None)
    async def mutate(audit: str, request: EvidenceRequest, authorized=Depends(machine)):
        return await service.mutate(audit, request.owner, request.probe_id)

    return app


def app():
    return create_app(Settings.from_env())
