from uuid import uuid4

from fastapi import Depends, FastAPI, Header
from hgs.models import AttackHypothesis, AttackSequenceStep

from penagent_common.api import BodyLimit, correlation, install_cors, install_errors, owner_dependency
from penagent_common.config import Settings
from penagent_common.http import service_call
from penagent_common.models import ApprovalDecision, AuditCreate, ExecuteInput, GuidedStepInput, Probe, RunInput, StateWrite, ExecutionResult, SessionState
from penagent_common.policy import Rejected
from penagent_common.store import Store
from executor.service import Executor, public_result
from executor.tools import Tools
from executor.workflow import Workflow


def create_app(settings: Settings) -> FastAPI:
    if not settings.api_tokens or not settings.service_token:
        raise ValueError("api_tokens and PENAGENT_SERVICE_TOKEN are required")
    app = FastAPI(title="PenAgent Component 3: Live Probe Executor", version="0.1.0")
    app.add_middleware(BodyLimit, limit=settings.max_request_size)
    install_cors(app)
    store = Store(settings)
    executor = Executor(settings, store)
    app.state.executor = executor
    owner = owner_dependency(settings)
    install_errors(app)

    @app.get("/health")
    async def health():
        return {"status": "healthy", "component": 3}

    @app.get("/ready")
    async def ready():
        from penagent_common.http import service_call
        with store.connection() as db:
            db.execute("SELECT 1")
        for base in (settings.sis_url, settings.hgs_url, settings.interpreter_url):
            await service_call(settings, "GET", base, "/health")
        return {"status": "ready"}

    @app.post("/v1/audits", status_code=201)
    async def create(request: AuditCreate, subject: str = Depends(owner)):
        if request.target_id not in settings.targets:
            raise Rejected("target_not_authorized")
        store.create(request.audit_id, subject, request.target_id)
        return {"audit_id": request.audit_id, "status": "PLANNING"}

    @app.get("/v1/audits")
    async def list_audits(subject: str = Depends(owner)):
        return {"audits": store.list_audits(subject)}

    @app.get("/v1/audits/{audit}")
    async def status(audit: str, subject: str = Depends(owner)):
        return {k: v for k, v in store.audit(audit, subject).items() if k != "owner"}

    @app.post("/v1/audits/{audit}/cancel")
    async def cancel(audit: str, subject: str = Depends(owner)):
        store.cancel(audit, subject)
        return {"status": "cancelled"}

    @app.post("/v1/audits/{audit}/probes", response_model=ExecutionResult)
    async def execute(audit: str, request: ExecuteInput, subject: str = Depends(owner), x_correlation_id: str | None = Header(default=None)):
        store.audit(audit, subject)
        result = await executor.execute(audit, subject, request.hypothesis, request.probe, correlation(x_correlation_id))
        return public_result(result)

    @app.get("/v1/audits/{audit}/probes/{probe}")
    async def get_probe(audit: str, probe: str, subject: str = Depends(owner)):
        item = store.get_probe(audit, subject, probe)
        return {"result": public_result(item["result"]) if item["result"] else None, "interpretation": item["interpretation"], "status": "recorded" if item["result"] else "outcome_unknown_do_not_replay"}

    @app.get("/v1/audits/{audit}/state", response_model=SessionState)
    async def state(audit: str, subject: str = Depends(owner)):
        return store.read(audit, subject)

    @app.put("/v1/audits/{audit}/state", response_model=SessionState)
    async def write_state(audit: str, request: StateWrite, subject: str = Depends(owner)):
        if request.key.startswith("__"):
            raise Rejected("reserved_state_key")
        return store.write(audit, subject, request)

    @app.get("/v1/audits/{audit}/evidence")
    async def evidence(audit: str, subject: str = Depends(owner)):
        trace = store.trace(audit, subject)
        # Never return raw request bindings, target text, session secrets, or
        # opaque observation values to the public evidence endpoint.
        return {"audit": trace["audit"], "probes": [{"probe_id": p["probe_id"],
                "result": public_result(p["result"]) if p["result"] else None,
                "interpretation": p["interpretation"]} for p in trace["probes"]],
                "transitions": [e for e in trace["events"] if e["kind"] == "transition"]}

    @app.get("/v1/audits/{audit}/approvals")
    async def approvals(audit: str, subject: str = Depends(owner)):
        return {"approvals": store.approvals(audit, subject)}

    @app.post("/v1/audits/{audit}/approvals/{probe}")
    async def decide_approval(audit: str, probe: str, request: ApprovalDecision, subject: str = Depends(owner), x_correlation_id: str | None = Header(default=None)):
        # Component 5: a human operator token holder is the reviewer. The decision
        # (approve/deny) is recorded atomically before the request is ever replayed.
        store.decide_approval(audit, subject, probe, "approved" if request.decision == "approve" else "denied", request.reason, subject)
        if request.decision == "approve":
            result = await executor.execute_approved(audit, subject, probe, correlation(x_correlation_id))
        else:
            result = executor.execute_denied(audit, subject, probe, request.reason)
        return public_result(result)

    @app.post("/v1/audits/{audit}/run")
    async def run(audit: str, request: RunInput, subject: str = Depends(owner), x_correlation_id: str | None = Header(default=None)):
        return await Workflow(executor).run(audit, subject, request.bindings, correlation(x_correlation_id))

    @app.post("/v1/audits/{audit}/guided-step")
    async def guided_step(audit: str, request: GuidedStepInput, subject: str = Depends(owner), x_correlation_id: str | None = Header(default=None)):
        # Lets a UI/demo caller drive one exact, pre-authored op+binding through
        # execute -> interpret in a single call, using only the operator token
        # it already has -- the server, not the caller, holds the machine token
        # needed to reach C4, same as /run already does internally.
        store.audit(audit, subject)
        hypothesis = AttackHypothesis(id=f"{audit}-{request.op}-{uuid4().hex[:8]}", target_endpoints=[request.op],
            owasp_category=request.owasp_category, attack_sequence=[AttackSequenceStep(step=1, op=request.op)])
        probe = Probe(hypothesis_id=hypothesis.id, op=request.op, binding=request.binding)
        correlation_id = correlation(x_correlation_id)
        result = await executor.execute(audit, subject, hypothesis, probe, correlation_id)
        interpretation = None
        if result.status == "executed":
            try:
                interpretation = await service_call(settings, "POST", settings.interpreter_url, f"/v1/audits/{audit}/interpret",
                    payload={"owner": subject, "probe_id": result.probe_id}, correlation_id=correlation_id)
            except Rejected as exc:
                interpretation = {"error": str(exc)}
        return {"result": public_result(result), "interpretation": interpretation}

    @app.get("/v1/tools")
    async def tools(subject: str = Depends(owner)):
        return Tools.definitions()

    return app


def app():
    return create_app(Settings.from_env())
