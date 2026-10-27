"""Drives the real guided evaluation against the real benchmark container:
hypotheses built directly from demo/benchmark-data/ground_truth_chains.json
(demo/eval_targets.py), submitted straight through execute -> interpret ->
report. Tests execution, approval gating, classification and report
fidelity given a known attack path -- not discovery.

Fully-autonomous (zero-hint, real C1->C2->C3) discovery was evaluated in an
earlier pass and is no longer run here -- see docs/RESULTS.md's history for
why (a specific, documented architectural ceiling: HGS's candidate-
surfacing heuristics and the "never invent a path/body parameter outside an
explicit binding" safety rule, neither of which ground-truth expansion
changes). Repeating it added no new information, so it was dropped rather
than carried forward as noise alongside the guided numbers.

Requires the real benchmark container running (images/README.md):
    docker run -d --name penagent-testbed -p 18001:3000 -p 18002:8000 \
      -p 18003:8080 monisha117/penagent-target-env:latest

Usage: python -m demo.run_evaluation --output reports/eval
"""
import argparse
import asyncio
import json
import re
import secrets
import time
from pathlib import Path

from cryptography.fernet import Fernet
from sis.models import AuthInfo, EndpointGraph, EndpointNode, ParameterModel
from hgs.models import AttackHypothesis, AttackSequenceStep
from penagent_common.config import Settings
from penagent_common.models import Probe, StateWrite
from penagent_common.store import Store
from executor.service import Executor
from interpreter.service import Interpreter
from report.synth import build_report
from demo import eval_targets

BENCHMARK_DATA = Path(__file__).resolve().parent / "benchmark-data"
GROUND_TRUTH = json.loads((BENCHMARK_DATA / "ground_truth_chains.json").read_text(encoding="utf-8"))
TARGET_SPECS = {
    "dvws": {"base_url": eval_targets.DVWS, "ground_truth_key": "dvws"},
    "srebench-api": {"base_url": eval_targets.SREBENCH, "ground_truth_key": "srebench_api"},
    "juice-shop": {"base_url": eval_targets.JUICE_SHOP, "ground_truth_key": "juice_shop"},
}


def ground_truth_entries(key):
    target = GROUND_TRUTH["targets"][key]
    return target.get("key_ground_truth_vulns") or target.get("scenarios") or []


# ---------------------------------------------------------------------------
# Guided chains
#
# Each step is {"op": op_id, "binding": dict | ctx -> dict, "needs_auth": bool,
# "capture": (ctx, parsed_data) -> None | None}. A plain dict binding (the
# DVWS/SREBench-API norm -- nothing there needs a login first) still works
# unchanged; "binding" only needs to be callable for a step whose values
# depend on an earlier step's real response (Juice Shop's register -> login
# -> reuse-the-token chain).
# ---------------------------------------------------------------------------

GUIDED_CHAINS = {
    "dvws": [
        {"op": "op_get_account_api_v1_accounts__account_id__get", "binding": {"path": {"account_id": "2"}}},
        {"op": "op_login_api_v1_auth_login_post", "binding": {"body": {"username": "' OR '1'='1' -- ", "password": "x"}}},
        {"op": "op_update_profile_api_v1_accounts__account_id__profile_put", "binding": {"path": {"account_id": "1"}, "body": {"role": "admin"}}},
        {"op": "op_purge_cache_api_v1_admin_maintenance_purge_cache_delete", "binding": {}},
        {"op": "op_get_debug_env_api_v1_debug_env_get", "binding": {}},
    ],
    "srebench-api": [
        {"op": "op_get_user_profile_users_v1_profile__user_id__get", "binding": {"path": {"user_id": "usr_102"}}},
        {"op": "op_get_vault_document_vault_v1_documents__doc_id__get", "binding": {"path": {"doc_id": "doc_002"}, "headers": {"x-internal-service": "auth-service-internal"}}},
    ],
    "juice-shop": [
        {"op": "op_js_register", "binding": lambda ctx: {"body": {"email": ctx["email"], "password": ctx["password"], "passwordRepeat": ctx["password"], "role": "admin"}}},
        {"op": "op_admin_get_rest_admin_application-configuration", "binding": {}},
        {"op": "op_js_search_sqli", "binding": {"query": {"q": "a')) UNION SELECT sql, '2','3','4','5','6','7','8','9' FROM sqlite_master--"}}},
        {"op": "op_js_ftp_acquisitions", "binding": {}},
        {"op": "op_js_metrics", "binding": {}},
        {"op": "op_js_ftp_pkgbak", "binding": {}},
        # From here on, needs the token captured by the login step below.
        # The real Executor *can* auto-extract a response credential into
        # session state (service.py's _perform()), but only by walking a
        # declared response JSON schema on the EndpointNode -- these nodes
        # are hand-built here, not derived from a real ingested spec, so
        # there's no schema to walk. Captured in Python instead, same as
        # demo/explore_run.py's session-chained Juice Shop run.
        {"op": "op_js_login", "binding": lambda ctx: {"body": {"email": ctx["email"], "password": ctx["password"]}},
         "capture": lambda ctx, data: ctx.update(token=data["authentication"]["token"], bid=data["authentication"]["bid"])},
        {"op": "op_users_get_api_users_id", "binding": lambda ctx: {"path": {"id": "1"}, "session_ref": "session"}, "needs_auth": True},
        {"op": "op_js_basket_view_admin", "binding": lambda ctx: {"path": {"id": "1"}, "session_ref": "session"}, "needs_auth": True},
        {"op": "op_js_basketitem_negative", "binding": lambda ctx: {"body": {"ProductId": 1, "BasketId": ctx["bid"], "quantity": -5}, "session_ref": "session"}, "needs_auth": True},
        {"op": "op_js_checkout", "binding": lambda ctx: {"path": {"bid": str(ctx["bid"])}, "session_ref": "session"}, "needs_auth": True},
        {"op": "op_js_order_history", "binding": lambda ctx: {"session_ref": "session"}, "needs_auth": True},
    ],
}

# op_js_login/op_js_basketitem_negative/op_js_checkout aren't in
# eval_targets.juice_shop_operations() -- they're plumbing to reach
# op_js_basket_view_admin/op_js_order_history's real evidence, not
# ground-truth findings in their own right -- so they're declared here,
# directly, with no Expectation of their own.
_JUICE_SHOP_PLUMBING_OPS = {
    "op_js_login": {"method": "POST", "path": "/rest/user/login", "risk": "destructive",
                    "expectation": {"expected_behavior": "plumbing: establishes the session reused by later steps"}},
    "op_js_basketitem_negative": {"method": "POST", "path": "/api/BasketItems", "risk": "destructive",
                                   "expectation": {"expected_behavior": "plumbing: sets up the order evidenced by op_js_order_history"}},
    "op_js_checkout": {"method": "POST", "path": "/rest/basket/{bid}/checkout", "risk": "destructive",
                        "expectation": {"expected_behavior": "plumbing: completes the order evidenced by op_js_order_history"}},
}


# Ops whose binding supplies query-string values beyond plain path params --
# _params_for only derives path params from {placeholders} in the path
# string itself; a query param has to be declared explicitly or the
# executor's own policy check rejects it as "unknown_parameter".
_QUERY_PARAMS = {"op_js_search_sqli": ["q"]}


def _params_for(path, op_id=None):
    params = [ParameterModel(name=m, location="path", required=True, schema_type="string") for m in re.findall(r"\{(\w+)\}", path)]
    params += [ParameterModel(name=q, location="query", required=False, schema_type="string") for q in _QUERY_PARAMS.get(op_id, [])]
    return params


async def guided_run(target_id, operations, directory):
    chain = GUIDED_CHAINS[target_id]
    ops = dict(operations["operations"])
    if target_id == "juice-shop":
        ops.update(_JUICE_SHOP_PLUMBING_OPS)
        operations = {**operations, "operations": ops, "credential_refs": ["session"]}

    nodes = []
    for op_id, cfg in ops.items():
        needs_auth = any(s["op"] == op_id and s.get("needs_auth") for s in chain)
        nodes.append(EndpointNode(id=op_id, method=cfg["method"], path=cfg["path"], parameters=_params_for(cfg["path"], op_id),
            auth=AuthInfo(type="bearer", location="header") if needs_auth else AuthInfo(),
            request_body_schema={"type": "object"} if cfg["method"] in {"POST", "PUT", "PATCH"} and op_id != "op_js_checkout" else None))
    graph = EndpointGraph(target_id=target_id, graph_id="guided-eval", spec_hash="guided-eval",
        created_at="eval", updated_at="eval", nodes=nodes)

    settings = Settings(database=str(directory / f"{target_id}-guided.db"), encryption_key=Fernet.generate_key().decode(),
        service_token=secrets.token_urlsafe(32), api_tokens={"evaluator": secrets.token_urlsafe(32)},
        max_probes=len(chain) + 5, targets={target_id: operations})
    store = Store(settings)
    executor = Executor(settings, store)
    interpreter = Interpreter(settings, store)
    audit = target_id + "-guided-" + secrets.token_hex(3)
    store.create(audit, "evaluator", target_id)
    started = time.time()
    first_finding_at = None
    probe_statuses = []
    ctx = {"email": f"eval-{secrets.token_hex(6)}@test.local", "password": "Test1234!"}

    for i, step in enumerate(chain):
        op_id = step["op"]
        binding = step["binding"](ctx) if callable(step["binding"]) else step["binding"]
        if step.get("needs_auth"):
            store.write(audit, "evaluator", StateWrite(key="session", category="tokens", value=ctx["token"]))
        # Each probe gets its own hypothesis matching that op's own configured
        # owasp_category -- Expectation.owasp_categories restricts confirmation
        # to hypotheses in-category, so a single shared "guided-evaluation"
        # category would silently fail every match.
        categories = ops[op_id]["expectation"].get("owasp_categories") or []
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
            if "capture" in step and result.parsed and result.parsed.kind == "json":
                try:
                    step["capture"](ctx, result.parsed.data)
                except (KeyError, TypeError):
                    pass  # this step's response didn't have the shape we hoped for; dependent steps skip via missing-key below
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


# ---------------------------------------------------------------------------

async def main_async(output_prefix):
    directory = Path("runtime/eval")
    directory.mkdir(parents=True, exist_ok=True)
    guided_results = []

    for target_id in TARGET_SPECS:
        guided_ops = eval_targets.all_targets()[target_id]
        print(f"== guided: {target_id} ==")
        guided_results.append(await guided_run(target_id, guided_ops, directory))

    Path(f"{output_prefix}-guided.json").write_text(json.dumps(guided_results, indent=2), encoding="utf-8")
    print(json.dumps({"status": "DONE", "guided_targets": [r["target"] for r in guided_results]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/eval")
    args = parser.parse_args()
    asyncio.run(main_async(args.output))


if __name__ == "__main__":
    main()
