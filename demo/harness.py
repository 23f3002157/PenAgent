"""Real TCP servers, ephemeral ports, no Docker or external target required."""
import contextlib
import json
import secrets
import socket
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from cryptography.fernet import Fernet
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from penagent_common.config import Settings


@contextlib.contextmanager
def live_server(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False, lifespan="off", ws="none"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not server.started:
            if not thread.is_alive() or time.monotonic() >= deadline:
                raise RuntimeError("fixture server did not start")
            time.sleep(.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()
        if thread.is_alive():
            raise RuntimeError("fixture server did not stop")


def fixture_target(focused=False, include_error=False):
    app = FastAPI(openapi_url=None)
    app.state.requests = []
    properties = {name: {"type": "string"} for name in ["owner", "private_data", "signal", "missing_header", "object_id", "access_token"]}
    response = {"200": {"description": "Fixture object", "content": {"application/json": {"schema": {"type": "object", "properties": properties}}}}, "403": {"description": "Denied"}}
    spec = {"openapi": "3.0.3", "info": {"title": "Isolated PenAgent fixture", "version": "1"}, "paths": {
        "/admin/object": {"get": {"operationId": "fixture_object", "responses": response}},
        "/admin/denied": {"get": {"operationId": "fixture_denied", "responses": response}},
        "/objects/{object_id}": {"get": {"operationId": "fixture_dependent", "parameters": [{"name": "object_id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "security": [{"bearer": []}], "responses": response}},
        "/session": {"get": {"operationId": "fixture_session", "responses": response}}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}}
    if focused:
        spec["paths"] = {k: v for k, v in spec["paths"].items() if k.startswith("/admin/")}
    if include_error:
        spec["paths"]["/admin/error"] = {"get": {"operationId": "fixture_error", "responses": {"500": {"description": "Controlled synthetic error"}}}}

    @app.get("/openapi.json")
    async def openapi():
        return spec

    @app.get("/admin/object")
    async def object(x_test_context: str | None = Header(default=None), x_correlation_id: str | None = Header(default=None)):
        app.state.requests.append({"method": "GET", "path": "/admin/object", "context": x_test_context, "correlation_id": x_correlation_id})
        if x_test_context == "fixture-only":
            return {"owner": "tenant-b", "private_data": "SIMULATED PRIVATE DATA; no real account", "object_id": "fixture-object"}
        return {"signal": "restricted-object", "missing_header": "X-Test-Context", "object_id": "fixture-object"}

    @app.get("/admin/denied")
    async def denied():
        app.state.requests.append({"method": "GET", "path": "/admin/denied"})
        return JSONResponse(status_code=403, content={"message": "access denied"})

    @app.get("/admin/error")
    async def error():
        app.state.requests.append({"method": "GET", "path": "/admin/error"})
        return JSONResponse(status_code=500, content={"message": "controlled synthetic failure"})

    @app.get("/session")
    async def session():
        return {"object_id": "fixture-object", "access_token": "fixture-session-token-only"}

    @app.get("/objects/{object_id}")
    async def dependent(object_id: str, authorization: str | None = Header(default=None)):
        app.state.requests.append({"method": "GET", "path": "/objects/" + object_id, "session_used": authorization == "Bearer fixture-session-token-only"})
        if authorization != "Bearer fixture-session-token-only":
            return JSONResponse(status_code=403, content={"message": "denied"})
        return {"object_id": object_id, "owner": "tenant-a"}

    return app


@contextlib.contextmanager
def stack(directory, focused=False, settings_overrides=None):
    """Start the unchanged C1/C2 apps and new C3/C4 apps over actual HTTP."""
    from sis import api as sis_api
    from sis.main import app as sis_app
    from sis.service import SpecIngestionService
    from sis.storage import GraphStorage
    from hgs import api as hgs_api
    from hgs.main import app as hgs_app
    from hgs.service import HypothesisGenerationService
    from hgs.queue import PriorityQueue
    from hgs.planner import Planner
    from hgs.surfacer import CandidateSurfacer
    from executor.main import create_app as executor_app
    from interpreter.main import create_app as interpreter_app

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    old_sis, old_hgs = sis_api.service, hgs_api.service
    sis_api.service = SpecIngestionService(GraphStorage(str(directory / "sis.db")))
    # Explicitly disable external LLM calls in the deterministic fixture stack.
    planner = Planner()
    planner.anthropic_key = planner.openai_key = ""
    target_app = fixture_target(focused)
    try:
        with contextlib.ExitStack() as exits:
            target = exits.enter_context(live_server(target_app))
            sis = exits.enter_context(live_server(sis_app))
            hgs_api.service = HypothesisGenerationService(queue=PriorityQueue(str(directory / "hgs.db")), surfacer=CandidateSurfacer(sis), planner=planner)
            hgs = exits.enter_context(live_server(hgs_app))
            token, api_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            config = {"database": str(directory / "execution.db"), "encryption_key": Fernet.generate_key().decode(), "service_token": token,
                      "api_tokens": {"fixture-operator": api_token}, "sis_url": sis, "hgs_url": hgs, "requests_per_second": 100.0,
                      "targets": {"fixture": {"base_url": target, "credential_refs": ["op_fixture_session.access_token"], "operations": {
                          "op_fixture_object": {"method": "GET", "path": "/admin/object", "allowed_headers": ["X-Test-Context"],
                              "header_variations": {"X-Test-Context": ["fixture-only"]}, "expectation": {
                                  "expected_behavior": "Anonymous clients must not receive tenant-b private data", "protected_fields": ["private_data"],
                                  "signal_fields": ["signal"], "forbidden_values": {"owner": "tenant-b"}}},
                          "op_fixture_denied": {"method": "GET", "path": "/admin/denied"},
                          "op_fixture_session": {"method": "GET", "path": "/session", "response_credentials": ["access_token"]},
                          "op_fixture_dependent": {"method": "GET", "path": "/objects/{object_id}"}}}}}
            config.update(settings_overrides or {})
            settings = Settings.model_validate(config)
            c4 = exits.enter_context(live_server(interpreter_app(settings)))
            settings.interpreter_url = c4
            c3_app = executor_app(settings)
            c3 = exits.enter_context(live_server(c3_app))
            yield {"settings": settings, "sis": sis, "hgs": hgs, "c3": c3, "c4": c4, "target": target,
                   "target_app": target_app, "executor_app": c3_app, "owner": "fixture-operator",
                   "headers": {"Authorization": "Bearer " + api_token}, "machine_headers": {"Authorization": "Bearer " + token}}
    finally:
        sis_api.service, hgs_api.service = old_sis, old_hgs
        # Legacy C1/C2 sqlite connection context managers commit but do not
        # explicitly close their handles. Collect unreachable cursor/connection
        # cycles before TemporaryDirectory cleanup on Windows; no service edits.
        import gc
        gc.collect()


def ingest_and_plan(env):
    with httpx.Client(timeout=10, trust_env=False) as client:
        response = client.post(env["sis"] + "/v1/ingest", json={"target_id": "fixture", "base_url": env["target"], "spec_source": env["target"] + "/openapi.json"})
        response.raise_for_status()
        job = response.json()["job_id"]
        for _ in range(100):
            state = client.get(env["sis"] + "/v1/ingest/" + job).json()
            if state["status"] == "done":
                break
            if state["status"] == "failed":
                raise RuntimeError("fixture ingestion failed")
            time.sleep(.02)
        else:
            raise RuntimeError("fixture ingestion did not complete")
        response = client.post(env["hgs"] + "/v1/hypotheses/generate", json={"target_id": "fixture", "max_hypotheses": 20})
        response.raise_for_status()
        return response.json()


def demonstration(directory, settings_overrides=None, require_outcomes=True):
    with stack(directory, focused=True, settings_overrides=settings_overrides) as env:
        batch = ingest_and_plan(env)
        headers = {**env["headers"], "X-Correlation-ID": "local-demo"}
        # A workflow may include multiple sequential bounded model calls.
        with httpx.Client(timeout=max(30, (settings_overrides or {}).get("service_timeout", 10) * 3), trust_env=False, headers=headers) as client:
            create = client.post(env["c3"] + "/v1/audits", json={"audit_id": "demo", "target_id": "fixture", "acknowledged_authorization": True})
            create.raise_for_status()
            outcomes = []
            # Consume actual HGS queue. Explicit empty step bindings suppress
            # heuristic payload hints for read-only fixture endpoints.
            for _ in range(batch["count"] + 5):
                response = client.post(env["c3"] + "/v1/audits/demo/run", json={"bindings": {"1": {}}})
                response.raise_for_status()
                output = response.json()
                outcomes.append(output)
                if output["status"] == "queue_empty":
                    break
                if output["status"] == "blocked":
                    raise RuntimeError("fixture workflow blocked: " + output["error"])
                current = client.get(env["c3"] + "/v1/audits/demo/evidence").json()
                categories = {p["interpretation"]["classification"] for p in current["probes"] if p["interpretation"]}
                if {"CONFIRMED_VULNERABILITY", "NEGATIVE"}.issubset(categories):
                    break
            trace = client.get(env["c3"] + "/v1/audits/demo/evidence").json()
            categories = {p["interpretation"]["classification"] for p in trace["probes"] if p["interpretation"]}
            if require_outcomes:
                assert {"CONFIRMED_VULNERABILITY", "NEGATIVE"}.issubset(categories), categories
            return {"environment": "isolated loopback fixture; simulated positive only", "outcomes": outcomes, "trace": trace,
                    "target_requests": env["target_app"].state.requests}
