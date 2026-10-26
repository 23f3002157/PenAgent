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


def main():
    UI_DATA.mkdir(parents=True, exist_ok=True)
    (UI_DATA / "guided-chains.json").write_text(json.dumps(export_guided_chains(), indent=2), encoding="utf-8")
    (UI_DATA / "results.json").write_text(json.dumps(export_results(), indent=2), encoding="utf-8")
    print(json.dumps({"status": "exported", "dir": str(UI_DATA)}))


if __name__ == "__main__":
    main()
