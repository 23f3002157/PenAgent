"""Drives the real evaluation against the real benchmark container -- two
modes, never conflated (see docs/RESULTS.md and the plan this implements):

  autonomous: real C1 ingest -> real C2 hypothesis generation -> C3/C5/C4
    executed via /run with empty bindings, exactly like demo/docker_verify.py
    already does for the synthetic fixture. No ground-truth-specific hints
    are ever supplied. Whatever it finds, it found on its own.

  guided: hypotheses built directly from demo/benchmark-data/ground_truth_chains.json
    (demo/eval_targets.py), submitted straight through POST .../probes ->
    interpret -> (mutate if needed) -> report. Tests execution, approval
    gating, classification and report fidelity given a known attack path --
    not discovery.

Requires the real benchmark container running (images/README.md):
    docker run -d --name penagent-testbed -p 18001:3000 -p 18002:8000 \
      -p 18003:8080 monisha117/penagent-target-env:latest

Usage: python -m demo.run_evaluation --output reports/eval
"""
import argparse
import asyncio
import json
import secrets
import time
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
from sis.models import EndpointGraph, EndpointNode
from hgs.models import AttackHypothesis, AttackSequenceStep
from penagent_common.config import Settings
from penagent_common.models import Probe
from penagent_common.store import Store
from executor.service import Executor, public_result
from interpreter.service import Interpreter
from report.synth import build_report
from demo import eval_targets
from demo.harness import live_server

BENCHMARK_DATA = Path(__file__).resolve().parent / "benchmark-data"
GROUND_TRUTH = json.loads((BENCHMARK_DATA / "ground_truth_chains.json").read_text(encoding="utf-8"))
# Juice Shop's /assets/public/specs/openapi.json returns HTTP 200 but is the
# SPA's index.html, not a spec (verified live) -- its sample spec, copied
# locally from the container's /app/specs/, is used instead.
TARGET_SPECS = {
    "dvws": {"base_url": eval_targets.DVWS, "spec_url": eval_targets.DVWS + "/openapi.json", "ground_truth_key": "dvws"},
    "srebench-api": {"base_url": eval_targets.SREBENCH, "spec_url": eval_targets.SREBENCH + "/openapi.json", "ground_truth_key": "srebench_api"},
    "juice-shop": {"base_url": eval_targets.JUICE_SHOP, "spec_url": str(BENCHMARK_DATA / "specs" / "juice_shop_sample.json"), "ground_truth_key": "juice_shop"},
}
# Destructive/mass-assignment ops already proven live in prior sessions; the
# unattended autonomous loop approves these once for the record (a real
# operator decision an unattended run can't make for anything else) rather
# than treating every pause as a blanket deny.
APPROVE_ON_SIGHT = {
    "op_purge_cache_api_v1_admin_maintenance_purge_cache_delete",
    "op_update_profile_api_v1_accounts__account_id__profile_put",
    "op_users_delete_api_users_id",
}


def ground_truth_entries(key):
    target = GROUND_TRUTH["targets"][key]
    return target.get("key_ground_truth_vulns") or target.get("scenarios") or []


# ---------------------------------------------------------------------------
# Autonomous mode
# ---------------------------------------------------------------------------

async def autonomous_run(target_id, spec_info, operations, directory):
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
    from report.main import create_app as report_app
    import contextlib

    old_sis, old_hgs = sis_api.service, hgs_api.service
    sis_api.service = SpecIngestionService(GraphStorage(str(directory / f"{target_id}-sis.db")))
    planner = Planner()
    planner.anthropic_key = planner.openai_key = ""
    run = {"target": target_id, "mode": "autonomous", "started": time.time(), "probe_statuses": [],
           "replanning_transitions": 0, "hypotheses_processed": 0, "time_to_first_finding_seconds": None,
           "outcomes": [], "approvals": []}
    try:
        with contextlib.ExitStack() as exits:
            sis = exits.enter_context(live_server(sis_app))
            hgs_api.service = HypothesisGenerationService(queue=PriorityQueue(str(directory / f"{target_id}-hgs.db")), surfacer=CandidateSurfacer(sis), planner=planner)
            hgs = exits.enter_context(live_server(hgs_app))
            token, api_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            settings = Settings(database=str(directory / f"{target_id}-exec.db"), encryption_key=Fernet.generate_key().decode(),
                service_token=token, api_tokens={"evaluator": api_token}, sis_url=sis, hgs_url=hgs, requests_per_second=4.0,
                request_timeout=20, service_timeout=30, max_probes=40, targets={target_id: operations})
            c4 = exits.enter_context(live_server(interpreter_app(settings)))
            settings.interpreter_url = c4
            c3 = exits.enter_context(live_server(executor_app(settings)))
            c6 = exits.enter_context(live_server(report_app(settings)))
            headers = {"Authorization": "Bearer " + api_token}
            async with httpx.AsyncClient(timeout=30, trust_env=False, headers=headers) as client:

                async def call(base, method, path, payload=None, machine=False):
                    h = {"Authorization": "Bearer " + token} if machine else None
                    r = await client.request(method, base + path, json=payload, headers=h)
                    r.raise_for_status()
                    return r.json() if r.status_code != 204 else None

                job = await call(sis, "POST", "/v1/ingest", {"target_id": target_id, "base_url": spec_info["base_url"], "spec_source": spec_info["spec_url"]})
                for _ in range(100):
                    status = await call(sis, "GET", "/v1/ingest/" + job["job_id"])
                    if status["status"] == "done":
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise RuntimeError(f"{target_id}: spec ingestion timeout")
                graph = await call(sis, "GET", f"/v1/graph/{target_id}")
                run["graph_nodes"] = len(graph["nodes"])

                batch = await call(hgs, "POST", "/v1/hypotheses/generate", {"target_id": target_id, "max_hypotheses": 20})
                run["hypotheses_generated"] = batch["count"]

                audit = target_id + "-auto-" + secrets.token_hex(3)
                await call(c3, "POST", "/v1/audits", {"audit_id": audit, "target_id": target_id, "acknowledged_authorization": True})
                run["audit_id"] = audit
                first_finding_at = None

                for _ in range(min(60, (batch["count"] or 1) * 4 + 5)):
                    output = await call(c3, "POST", f"/v1/audits/{audit}/run", {"bindings": {"1": {}}})
                    run["outcomes"].append(output)
                    if output["status"] == "queue_empty":
                        break
                    if output["status"] == "awaiting_approval":
                        pending = await call(c3, "GET", f"/v1/audits/{audit}/approvals")
                        probe_entry = next((p for p in pending["approvals"] if p["status"] == "pending"), None)
                        op = (probe_entry or {}).get("description", {}).get("path", "")
                        matched_op = next((o for o, cfg in operations["operations"].items() if cfg["path"] == op), None)
                        decision = "approve" if matched_op in APPROVE_ON_SIGHT else "deny"
                        decided = await call(c3, "POST", f"/v1/audits/{audit}/approvals/{output['probe_id']}", {"decision": decision, "reason": "autonomous-eval"})
                        run["approvals"].append({"op": matched_op, "decision": decision, "result_status": decided["status"]})
                    if output["status"] in {"hypothesis_finished", "chain_halted", "duplicate", "queue_empty"}:
                        run["hypotheses_processed"] += 1
                    trace = await call(c3, "GET", f"/v1/audits/{audit}/evidence")
                    run["probe_statuses"] = [p["result"]["status"] for p in trace["probes"] if p["result"]]
                    run["replanning_transitions"] = sum(1 for t in trace["transitions"] if t["data"]["state"] == "REPLANNING")
                    if first_finding_at is None:
                        if any(p["interpretation"] and p["interpretation"]["classification"] in {"CONFIRMED_VULNERABILITY", "STRONG_SIGNAL"} for p in trace["probes"]):
                            first_finding_at = time.time()

                run["time_to_first_finding_seconds"] = (first_finding_at - run["started"]) if first_finding_at else None
                run["report"] = await call(c6, "GET", f"/v1/audits/{audit}/report")
    finally:
        sis_api.service, hgs_api.service = old_sis, old_hgs
    return run


# ---------------------------------------------------------------------------
# Guided mode
# ---------------------------------------------------------------------------

GUIDED_CHAINS = {
    "dvws": [
        ("op_get_account_api_v1_accounts__account_id__get", {"path": {"account_id": "2"}}),
        ("op_login_api_v1_auth_login_post", {"body": {"username": "' OR '1'='1' -- ", "password": "x"}}),
        ("op_update_profile_api_v1_accounts__account_id__profile_put", {"path": {"account_id": "1"}, "body": {"role": "admin"}}),
        ("op_purge_cache_api_v1_admin_maintenance_purge_cache_delete", {}),
        ("op_get_debug_env_api_v1_debug_env_get", {}),
    ],
    "srebench-api": [
        ("op_get_user_profile_users_v1_profile__user_id__get", {"path": {"user_id": "usr_102"}}),
        ("op_get_vault_document_vault_v1_documents__doc_id__get", {"path": {"doc_id": "doc_002"}, "headers": {"x-internal-service": "auth-service-internal"}}),
    ],
    "juice-shop": [
        # Email must be unique per run -- Juice Shop rejects a repeat
        # registration with 400, which previously showed up as a silent WEAK
        # observation instead of the real finding. Resolved at call time
        # (see guided_run) rather than hardcoded here.
        ("op_js_register", {"body": {"email": "__DYNAMIC__", "password": "Test1234!", "passwordRepeat": "Test1234!", "role": "admin"}}),
        ("op_admin_get_rest_admin_application-configuration", {}),
    ],
}


BODY_OPS = {"op_login_api_v1_auth_login_post", "op_update_profile_api_v1_accounts__account_id__profile_put", "op_js_register"}


async def guided_run(target_id, operations, directory):
    nodes = []
    for op_id, cfg in operations["operations"].items():
        nodes.append(EndpointNode(id=op_id, method=cfg["method"], path=cfg["path"],
            parameters=_params_for(cfg["path"]),
            request_body_schema={"type": "object"} if op_id in BODY_OPS else None))
    graph = EndpointGraph(target_id=target_id, graph_id="guided-eval", spec_hash="guided-eval",
        created_at="eval", updated_at="eval", nodes=nodes)

    settings = Settings(database=str(directory / f"{target_id}-guided.db"), encryption_key=Fernet.generate_key().decode(),
        service_token=secrets.token_urlsafe(32), api_tokens={"evaluator": secrets.token_urlsafe(32)},
        targets={target_id: operations})
    store = Store(settings)
    executor = Executor(settings, store)
    interpreter = Interpreter(settings, store)
    audit = target_id + "-guided-" + secrets.token_hex(3)
    store.create(audit, "evaluator", target_id)
    started = time.time()
    first_finding_at = None
    probe_statuses = []

    for i, (op_id, binding) in enumerate(GUIDED_CHAINS[target_id]):
        if isinstance(binding.get("body"), dict) and binding["body"].get("email") == "__DYNAMIC__":
            binding = dict(binding, body=dict(binding["body"], email=f"eval-{secrets.token_hex(6)}@test.local"))
        # Each probe gets its own hypothesis matching that op's own configured
        # owasp_category -- Expectation.owasp_categories restricts confirmation
        # to hypotheses in-category, so a single shared "guided-evaluation"
        # category would silently fail every match.
        categories = operations["operations"][op_id]["expectation"].get("owasp_categories") or []
        hypothesis = AttackHypothesis(id=f"{target_id}-guided-{i}", target_endpoints=[op_id],
            owasp_category=(categories[0] if categories else "guided-evaluation"),
            attack_sequence=[AttackSequenceStep(step=1, op=op_id)])
        probe = Probe(hypothesis_id=hypothesis.id, op=op_id, binding=binding, depth=0)
        result = await executor.execute(audit, "evaluator", hypothesis, probe, f"guided-{i}", graph)
        probe_statuses.append(result.status)
        if result.status == "awaiting_approval":
            store.decide_approval(audit, "evaluator", result.probe_id, "approved", "guided evaluation: known ground-truth action", "evaluator")
            result = await executor.execute_approved(audit, "evaluator", result.probe_id, f"guided-{i}-approved")
            probe_statuses[-1] = result.status
        if result.status == "executed":
            interpretation = await interpreter.interpret(audit, "evaluator", result.probe_id)
            if first_finding_at is None and interpretation.classification.value in {"CONFIRMED_VULNERABILITY", "STRONG_SIGNAL"}:
                first_finding_at = time.time()

    trace = store.trace(audit, "evaluator")
    replanning = sum(1 for e in trace["events"] if e["kind"] == "transition" and e["data"]["state"] == "REPLANNING")
    report = build_report(audit, target_id, trace, settings.targets)
    return {"target": target_id, "mode": "guided", "audit_id": audit, "probe_statuses": probe_statuses,
            "replanning_transitions": replanning, "hypotheses_processed": 1,
            "time_to_first_finding_seconds": (first_finding_at - started) if first_finding_at else None,
            "report": report.model_dump(mode="json")}


def _params_for(path):
    import re
    from sis.models import ParameterModel
    return [ParameterModel(name=m, location="path", required=True, schema_type="string") for m in re.findall(r"\{(\w+)\}", path)]


# ---------------------------------------------------------------------------

async def main_async(output_prefix):
    directory = Path("runtime/eval")
    directory.mkdir(parents=True, exist_ok=True)
    autonomous_results, guided_results = [], []

    for target_id, spec_info in TARGET_SPECS.items():
        autonomous_ops = eval_targets.all_targets("autonomous")[target_id]
        print(f"== autonomous: {target_id} ==")
        autonomous_results.append(await autonomous_run(target_id, spec_info, autonomous_ops, directory))

    for target_id, spec_info in TARGET_SPECS.items():
        guided_ops = eval_targets.all_targets("guided")[target_id]
        print(f"== guided: {target_id} ==")
        guided_results.append(await guided_run(target_id, guided_ops, directory))

    Path(f"{output_prefix}-autonomous.json").write_text(json.dumps(autonomous_results, indent=2), encoding="utf-8")
    Path(f"{output_prefix}-guided.json").write_text(json.dumps(guided_results, indent=2), encoding="utf-8")
    print(json.dumps({"status": "DONE", "autonomous_targets": [r["target"] for r in autonomous_results],
                       "guided_targets": [r["target"] for r in guided_results]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/eval")
    args = parser.parse_args()
    asyncio.run(main_async(args.output))


if __name__ == "__main__":
    main()
