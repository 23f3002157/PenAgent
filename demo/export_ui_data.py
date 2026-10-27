"""Exports the guided-chain definitions and final evaluation/baseline results
to static JSON the UI reads directly -- one source of truth (this Python
code and the real run artifacts), no hand-duplicated data in JavaScript.

Usage: python -m demo.export_ui_data
"""
import json
from pathlib import Path

from demo.eval_targets import all_targets
from demo.evaluate import compute_metrics
from demo.run_evaluation import GUIDED_CHAINS, TARGET_SPECS, _JUICE_SHOP_PLUMBING_OPS, ground_truth_entries

UI_DATA = Path(__file__).resolve().parent.parent / "ui" / "data"


def export_guided_chains():
    operations_by_target = {t: all_targets()[t]["operations"] for t in GUIDED_CHAINS}
    operations_by_target["juice-shop"] = {**operations_by_target["juice-shop"], **_JUICE_SHOP_PLUMBING_OPS}
    # A dummy context so callable bindings (Juice Shop's register -> login ->
    # reuse-the-token chain) resolve to *something* exportable -- the UI's
    # guided-run panel drives independent single-shot probes and doesn't
    # (yet) thread a captured token across clicks, so a session-dependent
    # step exports with placeholder values and a flag the UI can show.
    dummy_ctx = {"email": "__DYNAMIC__", "password": "Test1234!", "token": "__NEEDS_LIVE_SESSION__", "bid": "__NEEDS_LIVE_SESSION__"}
    chains = {}
    for target_id, steps in GUIDED_CHAINS.items():
        ops = operations_by_target[target_id]
        chains[target_id] = []
        for step in steps:
            op_id = step["op"]
            categories = ops[op_id]["expectation"].get("owasp_categories") or []
            try:
                binding = step["binding"](dummy_ctx) if callable(step["binding"]) else step["binding"]
            except (KeyError, TypeError):
                binding = {}
            chains[target_id].append({
                "op": op_id, "method": ops[op_id]["method"], "path": ops[op_id]["path"],
                "owasp_category": categories[0] if categories else "guided-demo",
                "binding": binding, "needs_live_session": bool(step.get("needs_auth")),
            })
    return chains


# Real parameter counts and quantization, read from `ollama show <model>` --
# not estimated. Lets the comparison view show whether raw model size tracks
# with baseline accuracy (it doesn't: qwen-latest is the largest and the
# least accurate of the six).
MODEL_INFO = {
    "gemma3-1b-it-qat": {"label": "Gemma 3 1B", "params_b": 1.0, "quant": "Q4_0"},
    "gemma2-2b": {"label": "Gemma 2 2B", "params_b": 2.6, "quant": "Q4_0"},
    "llama3.2-3b": {"label": "Llama 3.2 3B", "params_b": 3.2, "quant": "Q4_K_M"},
    "phi3-latest": {"label": "Phi-3 3.8B", "params_b": 3.8, "quant": "Q4_0"},
    "qwen-latest": {"label": "Qwen2 4B", "params_b": 4.0, "quant": "Q4_0"},
    "gemma3-4b": {"label": "Gemma 3 4B", "params_b": 4.3, "quant": "Q4_K_M"},
}
_AVG_KEYS = ["true_positive_rate", "false_positive_rate", "precision", "recall", "f1_score", "cvss_score_accuracy"]


def _average_metrics(metrics_list: list[dict]) -> dict:
    out = {}
    for key in _AVG_KEYS:
        values = [m[key] for m in metrics_list if m.get(key) is not None]
        out[key] = round(sum(values) / len(values), 3) if values else None
    return out


def export_comparison(results: dict) -> dict:
    """Aggregate, across all 3 targets, PenAgent (guided) against every local
    Ollama baseline model -- the head-to-head the paper's Section 6.3 asks
    for, computed from the same per-target metrics already in results.json,
    not re-derived by hand. Fully-autonomous zero-hint discovery is no
    longer run or reported -- see demo/run_evaluation.py's module docstring
    for why repeating it added no new information."""
    targets = list(results["penagent"].keys())
    rows = []
    per_target = [results["penagent"][t]["guided"] for t in targets if "guided" in results["penagent"][t]]
    if per_target:
        rows.append({"id": "penagent-guided", "label": "PenAgent (guided)", "is_penagent": True,
                     "metrics": _average_metrics(per_target), "params_b": None, "quant": None})
    for model, per_target_map in results["baseline"].items():
        per_target = [per_target_map[t]["metrics"] for t in targets if t in per_target_map]
        if not per_target:
            continue
        info = MODEL_INFO.get(model, {"label": model, "params_b": None, "quant": None})
        wall_clock = [per_target_map[t]["wall_clock"] for t in targets if t in per_target_map]
        rows.append({"id": model, "label": info["label"], "is_penagent": False,
                     "metrics": _average_metrics(per_target), "params_b": info["params_b"], "quant": info["quant"],
                     "avg_wall_clock_seconds": round(sum(wall_clock) / len(wall_clock), 2) if wall_clock else None})
    return {"targets": targets, "rows": rows}


def export_results():
    repo = Path(__file__).resolve().parent.parent
    result = {"penagent": {}, "baseline": {}}
    path = repo / "reports" / "eval-final-guided.json"
    if path.exists():
        for run in json.loads(path.read_text()):
            gt = ground_truth_entries(TARGET_SPECS[run["target"]]["ground_truth_key"])
            result["penagent"].setdefault(run["target"], {})["guided"] = compute_metrics(run, gt)
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
    direct = run["direct"]
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
    results = export_results()
    (UI_DATA / "guided-chains.json").write_text(json.dumps(export_guided_chains(), indent=2), encoding="utf-8")
    (UI_DATA / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (UI_DATA / "comparison.json").write_text(json.dumps(export_comparison(results), indent=2), encoding="utf-8")
    (UI_DATA / "explore.json").write_text(json.dumps(export_explore(), indent=2), encoding="utf-8")
    print(json.dumps({"status": "exported", "dir": str(UI_DATA)}))


if __name__ == "__main__":
    main()
