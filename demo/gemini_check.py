"""Safe credential/model discovery. Never prints credentials or error bodies."""
import argparse
import asyncio
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from penagent_common.config import Settings
from penagent_common.policy import Rejected
from interpreter.gemini import GeminiProvider


async def check(model=None):
    load_dotenv(".env", override=False)
    key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not key:
        return {"status": "BLOCKED", "reason": "gemini_credentials_missing"}
    from google import genai
    from google.genai import types
    try:
        # Do not select an assumed model: discover the key's visible catalogue.
        with genai.Client(api_key=key, vertexai=False, http_options=types.HttpOptions(timeout=15000, retry_options=types.HttpRetryOptions(attempts=1))) as client:
            visible = [m.name.removeprefix("models/") for m in client.models.list() if "generateContent" in (m.supported_actions or [])]
    except Exception as error:
        code = getattr(error, "code", None)
        return {"status": "BLOCKED", "reason": "model_catalogue_unavailable", "http_status": code if isinstance(code, int) else None}
    selected = model or os.getenv("GEMINI_MODEL")
    if not selected:
        return {"status": "MODEL_SELECTION_REQUIRED", "available_models": visible}
    if selected.removeprefix("models/") not in visible:
        return {"status": "BLOCKED", "reason": "configured_model_not_in_catalogue", "model": selected}
    settings = Settings(llm_provider="gemini", llm_model=selected, gemini_key=key, llm_timeout=25.0)
    provider = GeminiProvider(settings)
    try:
        output = await provider.recommend({"classification": "STRONG_SIGNAL", "status_code": 200,
            "allowed_headers": {"X-Test-Context": ["fixture-only"]},
            "observations": {"missing_header": "X-Test-Context", "signal_fields_present": ["signal"]}, "predicate_satisfied": False})
        return {"status": "PASSED", "model": selected, "provider_calls": provider.calls, "usage": provider.last_usage,
                "schema_valid": True, "recommendation": output.model_dump()}
    except Rejected as error:
        return {"status": "BLOCKED", "reason": str(error), "model": selected, "provider_calls": provider.calls, "diagnostic": provider.last_error}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model")
    parser.add_argument("--output", default="reports/gemini-provider.json")
    args = parser.parse_args()
    result = asyncio.run(check(args.model))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
