"""Exports the guided-chain definitions and final evaluation/baseline results
to static JSON the UI reads directly -- one source of truth (this Python
code and the real run artifacts), no hand-duplicated data in JavaScript.

Usage: python -m demo.export_ui_data
"""
import json
from pathlib import Path

from demo.eval_targets import all_targets
from demo.evaluate import compute_metrics
from demo.run_evaluation import GUIDED_CHAINS, TARGET_SPECS, ground_truth_entries

UI_DATA = Path(__file__).resolve().parent.parent / "ui" / "data"


def export_guided_chains():
    operations_by_target = {t: all_targets("guided")[t]["operations"] for t in GUIDED_CHAINS}
    chains = {}
    for target_id, steps in GUIDED_CHAINS.items():
        ops = operations_by_target[target_id]
        chains[target_id] = []
        for op_id, binding in steps:
            categories = ops[op_id]["expectation"].get("owasp_categories") or []
            chains[target_id].append({
                "op": op_id, "method": ops[op_id]["method"], "path": ops[op_id]["path"],
                "owasp_category": categories[0] if categories else "guided-demo",
                "binding": binding,
            })
    return chains


def export_results():
    repo = Path(__file__).resolve().parent.parent
    result = {"penagent": {}, "baseline": {}}
    for mode, filename in [("autonomous", "eval-final-autonomous.json"), ("guided", "eval-final-guided.json")]:
        path = repo / "reports" / filename
        if not path.exists():
            continue
        for run in json.loads(path.read_text()):
            gt = ground_truth_entries(TARGET_SPECS[run["target"]]["ground_truth_key"])
            result["penagent"].setdefault(run["target"], {})[mode] = compute_metrics(run, gt)
    for path in sorted((repo / "reports").glob("baseline-final-*.json")):
        model = path.stem.split("baseline-final-")[1]
        for run in json.loads(path.read_text()):
            gt = ground_truth_entries(TARGET_SPECS[run["target"]]["ground_truth_key"])
            m = compute_metrics(run, gt)
            result["baseline"].setdefault(model, {})[run["target"]] = {
                "metrics": m, "wall_clock": run["wall_clock_seconds"], "n_findings": len(run["report"]["findings"])}
    return result


def _status_bucket(code):
    if code is None:
        return "other"
    if code in (401, 403):
        return "protected"
    if 200 <= code < 300:
        return "exposed"
    if code >= 500:
        return "crash"
    return "other"


# Resource groupings for the category breakdown chart -- first matching
# prefix wins, checked in order (most specific first).
_JUICE_SHOP_CATEGORIES = [
    ("/rest/admin", "Admin"),
    ("/rest/2fa", "Account security"),
    ("/rest/user", "Identity & auth"),
    ("/api/Users", "Identity & auth"),
    ("/rest/basket", "Basket & checkout"),
    ("/api/BasketItems", "Basket & checkout"),
    ("/rest/order-history", "Orders"),
    ("/rest/track-order", "Orders"),
    ("/rest/continue-code", "Orders"),
    ("/api/Products", "Products & reviews"),
    ("/rest/products", "Products & reviews"),
    ("/api/Addresss", "Payment & address"),
    ("/api/Cards", "Payment & address"),
    ("/rest/wallet", "Payment & address"),
    ("/rest/deluxe-membership", "Payment & address"),
    ("/api/Feedbacks", "Feedback & records"),
    ("/api/Complaints", "Feedback & records"),
    ("/api/PrivacyRequests", "Feedback & records"),
    ("/api/SecurityQuestions", "Feedback & records"),
    ("/api/SecurityAnswers", "Feedback & records"),
    ("/api/Quantitys", "Feedback & records"),
    ("/api/Recycles", "Feedback & records"),
    ("/rest/memories", "Account features"),
    ("/rest/captcha", "Account features"),
]
_DVWS_CATEGORIES = [
    ("/api/v1/accounts", "Accounts"),
    ("/api/v1/auth", "Auth"),
    ("/api/v1/admin", "Admin"),
    ("/api/v1/debug", "Admin"),
    ("/api/v1/export", "Admin"),
]


def _categorize(target_id, path):
    table = _JUICE_SHOP_CATEGORIES if target_id == "juice-shop" else _DVWS_CATEGORIES
    for prefix, label in table:
        if path.startswith(prefix):
            return label
    return "Other"


def _explore_target(target_id: str, run: dict, operations: dict) -> dict:
    direct, autonomous = run["direct"], run["autonomous"]
    buckets = {"protected": 0, "exposed": 0, "crash": 0, "other": 0}
    category_breakdown = {}
    method_breakdown = {}
    outcomes = []
    for o in direct["op_outcomes"]:
        cfg = operations["operations"].get(o["op"], {})
        method, path = cfg.get("method", "?"), cfg.get("path", o["op"])
        category = _categorize(target_id, path)
        bucket = _status_bucket(o["status_code"])
        buckets[bucket] += 1
        category_breakdown.setdefault(category, {"protected": 0, "exposed": 0, "crash": 0, "other": 0})[bucket] += 1
        method_breakdown[method] = method_breakdown.get(method, 0) + 1
        outcomes.append({**o, "method": method, "path": path, "category": category})
    return {
        "ops_authorized": run["ops_authorized"],
        "status_buckets": buckets,
        "category_breakdown": category_breakdown,
        "method_breakdown": method_breakdown,
        "op_outcomes": outcomes,
        "direct_findings": direct["report"]["findings"],
        "autonomous_findings": autonomous["report"]["findings"],
        "autonomous_probes": len(autonomous.get("probe_statuses", [])),
        "direct_probes": len(direct["probe_statuses"]),
        "challenge_delta": run.get("challenge_delta"),
    }


def _current_juice_shop_solved():
    """Live, current /api/Challenges state at export time -- richer than the
    run's own before/after delta, which reads 0 "newly solved" on a repeat
    export against a container that was never restarted between runs."""
    import httpx
    from demo import eval_targets
    try:
        r = httpx.get(eval_targets.JUICE_SHOP + "/api/Challenges", timeout=5)
        r.raise_for_status()
        data = r.json()
        solved = [c for c in data.get("data", data) if c.get("solved")]
        return {"total_solved": len(solved), "total_challenges": len(data.get("data", data)),
                "solved": [{"name": c["name"], "category": c["category"], "difficulty": c.get("difficulty")} for c in solved]}
    except Exception:
        return None


def export_explore():
    from demo.explore_run import dvws_full_operations, juice_shop_full_operations
    repo = Path(__file__).resolve().parent.parent
    operations_by_target = {"juice-shop": juice_shop_full_operations(), "dvws": dvws_full_operations()}
    result = {}
    for target_id in ("juice-shop", "dvws"):
        path = repo / "reports" / f"explore-{target_id}.json"
        if path.exists():
            run = json.loads(path.read_text(encoding="utf-8"))
            result[target_id] = _explore_target(target_id, run, operations_by_target[target_id])
    if "juice-shop" in result:
        live_solved = _current_juice_shop_solved()
        if live_solved:
            result["juice-shop"]["current_solved"] = live_solved
    return result


def main():
    UI_DATA.mkdir(parents=True, exist_ok=True)
    (UI_DATA / "guided-chains.json").write_text(json.dumps(export_guided_chains(), indent=2), encoding="utf-8")
    (UI_DATA / "results.json").write_text(json.dumps(export_results(), indent=2), encoding="utf-8")
    (UI_DATA / "explore.json").write_text(json.dumps(export_explore(), indent=2), encoding="utf-8")
    print(json.dumps({"status": "exported", "dir": str(UI_DATA)}))


if __name__ == "__main__":
    main()
