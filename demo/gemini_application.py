"""Live Gemini through the actual C1→C2→C3↔C4 application HTTP path."""
import argparse
import json
import os
import tempfile
from pathlib import Path
from dotenv import load_dotenv
from demo.harness import demonstration


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/gemini-application.json")
    args = parser.parse_args()
    load_dotenv(".env", override=False)
    key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL")
    if not key or not model:
        print(json.dumps({"status": "BLOCKED", "reason": "gemini_credentials_or_model_missing"}))
        return
    with tempfile.TemporaryDirectory(prefix="penagent-gemini-") as directory:
        result = demonstration(directory, {"llm_provider": "gemini", "llm_model": model, "gemini_key": key,
            "llm_timeout": 60.0, "service_timeout": 90.0, "max_duration": 600.0}, require_outcomes=False)
    assessments = [p["interpretation"].get("model_assessment") for p in result["trace"]["probes"] if p["interpretation"]]
    invoked = any(a and a["provider"] == "gemini" and a["schema_valid"] for a in assessments)
    categories = {p["interpretation"]["classification"] for p in result["trace"]["probes"] if p["interpretation"]}
    passed = invoked and {"STRONG_SIGNAL", "CONFIRMED_VULNERABILITY", "NEGATIVE"}.issubset(categories)
    result.update(status="PASSED" if passed else "FAILED", model=model, assessments=assessments)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "model": model, "probes": len(result["trace"]["probes"]), "gemini_calls": result["trace"]["audit"]["llm_calls"],
        "usage": [a["usage"] for a in assessments if a], "outcomes": [{"classification": p["interpretation"]["classification"], "action": p["interpretation"]["next_action"], "error": p["interpretation"]["error"]} for p in result["trace"]["probes"] if p["interpretation"]]}))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
