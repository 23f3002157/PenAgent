"""Verify real container HTTP flow against a synthetic isolated fixture only."""
import argparse
import json
import time
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4
import httpx
from dotenv import dotenv_values


def environment():
    values = dotenv_values(".env")
    tokens = json.loads(values["PENAGENT_API_TOKENS"])
    owner, token = next(iter(tokens.items()))
    return {"owner": owner, "headers": {"Authorization": "Bearer " + token},
        "machine_headers": {"Authorization": "Bearer " + values["PENAGENT_SERVICE_TOKEN"]},
        **{name: "http://127.0.0.1:" + values.get(var, default) for name, var, default in [
            ("sis", "SIS_HOST_PORT", "9001"), ("hgs", "HGS_HOST_PORT", "9002"),
            ("executor", "EXECUTOR_HOST_PORT", "9003"), ("interpreter", "INTERPRETER_HOST_PORT", "9004")]}}


def verify(require_gemini=False):
    env = environment()
    config = json.loads(Path("runtime/docker.json").read_text(encoding="utf-8"))
    target = config["targets"]["fixture"]["base_url"]
    audit = "docker-" + uuid4().hex[:10]
    with httpx.Client(timeout=90, trust_env=False, headers=env["headers"]) as client:
        def call(service, method, path, payload=None, machine=False):
            response = client.request(method, env[service] + path, json=payload,
                headers=env["machine_headers"] if machine else None)
            response.raise_for_status()
            return response.json() if response.status_code != 204 else None
        health = {name: call(name, "GET", "/health") for name in ("sis", "hgs", "executor", "interpreter")}
        readiness = {name: call(name, "GET", "/ready") for name in ("executor", "interpreter")}
        assert client.get(env["interpreter"] + "/v1/audits/missing/interpret").status_code == 405
        assert client.post(env["interpreter"] + "/v1/audits/missing/interpret", json={"owner": env["owner"], "probe_id": "fake"}).status_code == 401
        job = call("sis", "POST", "/v1/ingest", {"target_id": "fixture", "base_url": target, "spec_source": target + "/openapi.json"})
        for _ in range(100):
            status = call("sis", "GET", "/v1/ingest/" + job["job_id"])
            if status["status"] == "done":
                break
            assert status["status"] != "failed", "fixture ingestion failed"
            time.sleep(.1)
        else:
            raise RuntimeError("fixture ingestion timeout")
        graph = call("sis", "GET", "/v1/graph/fixture")
        batch = call("hgs", "POST", "/v1/hypotheses/generate", {"target_id": "fixture", "max_hypotheses": 20})
        assert batch["hypotheses"] and graph["nodes"]
        call("executor", "POST", "/v1/audits", {"audit_id": audit, "target_id": "fixture", "acknowledged_authorization": True})
        outcomes = []
        for _ in range(batch["count"] + 5):
            # The intentional 500 belongs to its own audit: mixing it into the
            # positive/negative chain would correctly halt that entire audit.
            pending = call("hgs", "GET", "/v1/queue/fixture")
            while pending and any(s["op"] == "op_fixture_error" for s in pending[0]["attack_sequence"]):
                call("hgs", "GET", "/v1/queue/fixture/next")
                pending = call("hgs", "GET", "/v1/queue/fixture")
            output = call("executor", "POST", f"/v1/audits/{audit}/run", {"bindings": {"1": {}}})
            outcomes.append(output)
            trace = call("executor", "GET", f"/v1/audits/{audit}/evidence")
            categories = {p["interpretation"]["classification"] for p in trace["probes"] if p["interpretation"]}
            if {"CONFIRMED_VULNERABILITY", "NEGATIVE"}.issubset(categories):
                break
            if output["status"] not in {"hypothesis_finished", "duplicate", "chain_halted"}:
                raise RuntimeError("workflow did not complete: " + json.dumps(output))
        assert {"STRONG_SIGNAL", "CONFIRMED_VULNERABILITY", "NEGATIVE"}.issubset(categories), categories
        assessments = [p["interpretation"].get("model_assessment") for p in trace["probes"] if p["interpretation"]]
        if require_gemini:
            assert any(a and a["provider"] == "gemini" and a["schema_valid"] for a in assessments), "Gemini was not invoked successfully through C4"
        state = call("executor", "GET", f"/v1/audits/{audit}/state")
        assert state["values"]["object_ids"]
        with closing(sqlite3.connect("runtime/docker-state/execution.db", timeout=10)) as database:
            handoffs = database.execute("SELECT kind,status FROM handoffs WHERE audit=?", (audit,)).fetchall()
        assert {("feedback", "done"), ("replan", "done")}.issubset(set(handoffs))
        error_audit = audit + "-error"
        call("executor", "POST", "/v1/audits", {"audit_id": error_audit, "target_id": "fixture", "acknowledged_authorization": True})
        error_hyp = next(h for h in batch["hypotheses"] if any(s["op"] == "op_fixture_error" for s in h["attack_sequence"]))
        request = {"hypothesis": error_hyp, "probe": {"hypothesis_id": error_hyp["id"], "op": "op_fixture_error"}}
        error_result = call("executor", "POST", f"/v1/audits/{error_audit}/probes", request)
        assert error_result["status_code"] == 500
        error_interpretation = call("interpreter", "POST", f"/v1/audits/{error_audit}/interpret", {"owner": env["owner"], "probe_id": error_result["probe_id"]}, machine=True)
        assert error_interpretation["classification"] == "ERROR_CRASH" and error_interpretation["next_action"] == "stop"
        halted = call("executor", "POST", f"/v1/audits/{error_audit}/probes", request)
        assert halted["attempts"] == 0 and halted["error"] == "service_chain_halted"
        call("executor", "POST", f"/v1/audits/{audit}/cancel")
        cancelled = call("executor", "POST", f"/v1/audits/{audit}/run", {"bindings": {}})
        assert cancelled["error"] == "cancelled"
        return {"status": "PASSED", "environment": "Docker synthetic fixture; no benchmark created", "audit_id": audit,
            "health": health, "readiness": readiness, "node_count": len(graph["nodes"]), "hypothesis_count": batch["count"],
            "outcomes": outcomes, "trace": trace, "state": state, "gemini_assessments": assessments,
            "controlled_error": error_interpretation, "repeat_after_error": halted, "cancellation": cancelled}


def restart_check(path):
    previous = json.loads(path.read_text(encoding="utf-8"))
    env = environment()
    with httpx.Client(timeout=10, trust_env=False, headers=env["headers"]) as client:
        for _ in range(60):
            try:
                ready = client.get(env["executor"] + "/ready")
                if ready.status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("services not ready after restart")
        response = client.get(env["executor"] + f"/v1/audits/{previous['audit_id']}/state")
        response.raise_for_status()
        assert response.json() == previous["state"], "state changed across restart"
        first = previous["trace"]["probes"][0]
        evidence = client.get(env["executor"] + f"/v1/audits/{previous['audit_id']}/probes/{first['probe_id']}")
        evidence.raise_for_status()
        assert evidence.json()["result"]["parsed"]["body_sha256"] == first["result"]["parsed"]["body_sha256"]
    previous["persistence_after_restart"] = True
    path.write_text(json.dumps(previous, indent=2), encoding="utf-8")
    print(json.dumps({"status": "PASSED", "persistence_after_restart": True, "audit_id": previous["audit_id"]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-gemini", action="store_true")
    parser.add_argument("--output", default="reports/docker-integration.json")
    parser.add_argument("--restart-check", action="store_true")
    args = parser.parse_args()
    if args.restart_check:
        return restart_check(Path(args.output))
    result = verify(args.require_gemini)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "audit_id": result["audit_id"], "probes": len(result["trace"]["probes"]), "gemini_verified": args.require_gemini, "controlled_error": result["controlled_error"]["classification"]}))


if __name__ == "__main__":
    main()
