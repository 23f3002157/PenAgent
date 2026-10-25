"""Explicit read-only C3→C4 check against an existing authorized Juice Shop.

No benchmark spec/dataset is written. The operator scopes only GET /; the full
C1/C2 workflow is verified separately against the isolated synthetic fixture.
"""
import argparse
import asyncio
import json
import secrets
import tempfile
from pathlib import Path
import httpx
from cryptography.fernet import Fernet
from hgs.models import AttackHypothesis, AttackSequenceStep
from sis.models import EndpointGraph, EndpointNode
from penagent_common.config import Settings
from penagent_common.models import Probe
from penagent_common.store import Store
from penagent_common.policy import origin
from executor.service import Executor, public_result
from interpreter.main import create_app
from demo.harness import live_server


async def check(url, directory):
    origin(url)
    node = EndpointNode(id="op_authorized_juice_root", method="GET", path="/")
    graph = EndpointGraph(target_id="juice-read-only", graph_id="operator-scope", spec_hash="operator-authorized-root-only",
        created_at="verification", updated_at="verification", nodes=[node])
    hypothesis = AttackHypothesis(id="juice-connectivity", target_endpoints=[node.id], owasp_category="API8:Security_Misconfiguration",
        attack_sequence=[AttackSequenceStep(step=1, op=node.id)])
    settings = Settings(database=str(Path(directory) / "state.db"), encryption_key=Fernet.generate_key().decode(),
        service_token=secrets.token_urlsafe(32), targets={"juice-read-only": {"base_url": url, "operations": {node.id: {"method": "GET", "path": "/"}}}})
    store = Store(settings)
    store.create("juice-read", "operator", "juice-read-only")
    result = await Executor(settings, store).execute("juice-read", "operator", hypothesis, Probe(hypothesis_id=hypothesis.id, op=node.id), "juice-read-only", graph)
    assert result.status == "executed" and result.status_code == 200, result.error
    with live_server(create_app(settings)) as c4:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            response = await client.post(c4 + "/v1/audits/juice-read/interpret", json={"owner": "operator", "probe_id": result.probe_id},
                headers={"Authorization": "Bearer " + settings.service_token})
            response.raise_for_status()
            interpretation = response.json()
    assert interpretation["classification"] != "CONFIRMED_VULNERABILITY"
    return {"status": "PASSED", "scope": "existing authorized target; GET / only; not a benchmark", "result": public_result(result), "interpretation": interpretation}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", default="reports/juice-read-only.json")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="penagent-juice-read-") as directory:
        result = asyncio.run(check(args.url, directory))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "http_status": result["result"]["status_code"], "classification": result["interpretation"]["classification"]}))


if __name__ == "__main__":
    main()
