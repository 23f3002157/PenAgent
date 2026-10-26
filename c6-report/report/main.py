from fastapi import Depends, FastAPI
from fastapi.responses import Response

from penagent_common.api import BodyLimit, install_cors, install_errors, owner_dependency
from penagent_common.config import Settings
from penagent_common.models import AuditReport
from penagent_common.store import Store
from report.pdf import build_pdf
from report.synth import build_report


def create_app(settings: Settings) -> FastAPI:
    if not settings.api_tokens:
        raise ValueError("api_tokens are required")
    app = FastAPI(title="PenAgent Component 6: Audit Report Generator", version="0.1.0")
    app.add_middleware(BodyLimit, limit=settings.max_request_size)
    install_cors(app)
    store = Store(settings)
    owner = owner_dependency(settings)
    install_errors(app)

    @app.get("/health")
    async def health():
        return {"status": "healthy", "component": 6}

    @app.get("/ready")
    async def ready():
        with store.connection() as db:
            db.execute("SELECT 1")
        return {"status": "ready"}

    @app.get("/v1/audits/{audit}/report", response_model=AuditReport)
    async def report(audit: str, subject: str = Depends(owner)):
        # Read-only over the same encrypted store C3/C4 already write to; callable
        # at any time and reflects whatever evidence has been collected so far.
        trace = store.trace(audit, subject)
        return build_report(audit, trace["audit"]["target"], trace, settings.targets)

    @app.get("/v1/audits/{audit}/report.pdf")
    async def report_pdf(audit: str, subject: str = Depends(owner)):
        # The actual document output: same evidence, same redaction guarantees,
        # rendered as a PDF instead of JSON. Not a separate out-of-band script.
        trace = store.trace(audit, subject)
        built = build_report(audit, trace["audit"]["target"], trace, settings.targets)
        pdf_bytes = build_pdf(built)
        headers = {"Content-Disposition": f'inline; filename="penagent-{audit}.pdf"'}
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)

    return app


def app():
    return create_app(Settings.from_env())
