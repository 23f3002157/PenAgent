import asyncio
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from hgs.models import AttackHypothesis, AttackSequenceStep
from sis.models import EndpointGraph
from executor.main import create_app
from executor.tools import Tools
from executor.workflow import Workflow
from penagent_common.models import Binding, Probe
from penagent_common.policy import Rejected
from demo.harness import stack, ingest_and_plan, demonstration


def test_live_closed_loop(tmp_path):
    report = demonstration(tmp_path)
    probes = report["trace"]["probes"]
    assert any(p["interpretation"]["classification"] == "STRONG_SIGNAL" for p in probes)
    assert any(p["interpretation"]["classification"] == "CONFIRMED_VULNERABILITY" for p in probes)
    assert any(p["interpretation"]["classification"] == "NEGATIVE" for p in probes)
    assert any(r.get("context") == "fixture-only" for r in report["target_requests"])
    assert all(r.get("correlation_id") == "local-demo" for r in report["target_requests"] if r["path"] == "/admin/object")


def test_contracts_sessions_and_endpoints(tmp_path):
    with stack(tmp_path) as env:
        batch = ingest_and_plan(env)
        with httpx.Client(timeout=20, trust_env=False, headers=env["headers"]) as c:
            graph = EndpointGraph.model_validate(c.get(env["sis"] + "/v1/graph/fixture").json())
            assert {"op_fixture_object", "op_fixture_session"}.issubset({n.id for n in graph.nodes})
            assert all(AttackHypothesis.model_validate(h) for h in batch["hypotheses"])
            assert c.get(env["c3"] + "/ready").status_code == 200
            assert c.get(env["c4"] + "/ready").status_code == 200
            assert c.post(env["c3"] + "/v1/audits", json={"audit_id": "sessions", "target_id": "fixture", "acknowledged_authorization": True}).status_code == 201
            hyp = AttackHypothesis(id="session-chain", target_endpoints=["op_fixture_session", "op_fixture_dependent"], owasp_category="API1:BOLA",
                attack_sequence=[AttackSequenceStep(step=1, op="op_fixture_session"), AttackSequenceStep(step=2, op="op_fixture_dependent")])
            def send(probe):
                response = c.post(env["c3"] + "/v1/audits/sessions/probes", json={"hypothesis": hyp.model_dump(mode="json"), "probe": probe.model_dump()})
                response.raise_for_status()
                return response.json()
            second = Probe(hypothesis_id=hyp.id, op="op_fixture_dependent", binding=Binding(path={"object_id": {"$state": "object_ids.op_fixture_session.object_id"}}, session_ref="op_fixture_session.access_token", depends_on=[1]))
            blocked = send(second)
            assert blocked["status"] == "blocked"
            first = send(Probe(hypothesis_id=hyp.id, op="op_fixture_session"))
            assert first["status"] == "executed"
            reused = send(second)
            assert reused["status_code"] == 200 and reused["status"] == "executed", reused
            assert env["target_app"].state.requests[-1]["session_used"] is True
            assert "fixture-session-token-only" not in c.get(env["c3"] + "/v1/audits/sessions/state").text
            assert c.get(env["c3"] + "/v1/audits/sessions/probes/" + reused["probe_id"]).status_code == 200
            assert c.get(env["c3"] + "/v1/tools").status_code == 200
            assert c.post(env["c3"] + "/v1/audits/sessions/cancel").status_code == 200
            assert send(second)["status"] == "cancelled"


def test_api_isolation_and_validation(settings):
    with TestClient(create_app(settings)) as client:
        alice = {"Authorization": "Bearer alice-test-only"}
        bob = {"Authorization": "Bearer bob-test-only"}
        assert client.get("/v1/audits/audit").status_code == 401
        assert client.post("/v1/audits", json={"audit_id": "audit", "target_id": "fixture", "acknowledged_authorization": True}, headers=alice).status_code == 201
        assert client.get("/v1/audits/audit/state", headers=bob).status_code == 404
        assert client.put("/v1/audits/audit/state", json={"category": "tokens", "key": "a", "value": "secret"}, headers=bob).status_code == 404
        assert client.post("/v1/audits", json={"audit_id": "a", "target_id": "fixture", "acknowledged_authorization": False}, headers=alice).status_code == 422
        assert client.post("/v1/audits/audit/probes", json={"made_up": "schema"}, headers=alice).status_code == 422
        assert client.get("/openapi.json").status_code == 200
        assert client.put("/v1/audits/audit/state", content=b"x" * (settings.max_request_size + 1), headers=alice).status_code == 413


async def test_all_four_bound_tools_over_live_target(tmp_path):
    with stack(tmp_path) as env:
        ingest_and_plan(env)
        ex = env["executor_app"].state.executor
        ex.store.create("tools", env["owner"], "fixture")
        hyp = AttackHypothesis(id="tools-hyp", target_endpoints=["op_fixture_object"], owasp_category="API5:BFLA", attack_sequence=[AttackSequenceStep(step=1, op="op_fixture_object")])
        tools = Tools(ex, "tools", env["owner"], hyp, Probe(hypothesis_id=hyp.id, op="op_fixture_object"), "tools-correlation")
        result = await tools.invoke("http_request", {"method": "GET", "url": env["target"] + "/admin/object"})
        assert result["status_code"] == 200, result
        parsed = await tools.invoke("parse_response", {"probe_id": result["probe_id"]})
        assert parsed["kind"] == "json"
        assert "op_fixture_object.object_id" in (await tools.invoke("read_session_state", {}))["values"]["object_ids"]
        state = await tools.invoke("write_session_state", {"category": "observations", "key": "observed", "value": "HTTP success with signal"})
        assert "observed" in state["values"]["observations"]
