"""Smoke verification against the real monisha117/penagent-target-env benchmark
container (Juice Shop / SREBench-API / DVWS), run locally per images/README.md:

    docker run -d --name penagent-testbed \\
      -p 18001:3000 -p 18002:8000 -p 18003:8080 \\
      monisha117/penagent-target-env:latest

(images/README.md names the image `penagent-test-env`; the image actually
published to Docker Hub under the `monisha117` account is `penagent-target-env`.)

This exercises the real C3 -> Component 5 (approval gate) -> C4 -> Component 6
(report) pipeline against three live, real targets, driven in-process with a
hand-built EndpointGraph/AttackHypothesis per target -- the same pattern
demo/juice_check.py already uses -- rather than a live C1/C2/HGS deployment.
It is a smoke/integration check, not a benchmark run: it does not attempt to
discover every documented vulnerability in these targets, and it creates no
benchmark specs, ground truth or datasets of its own.
"""
import argparse
import asyncio
import json
import secrets
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet
from sis.models import EndpointGraph, EndpointNode
from hgs.models import AttackHypothesis, AttackSequenceStep
from penagent_common.config import Expectation, OperationPolicy, Settings, TargetPolicy
from penagent_common.models import Probe
from penagent_common.policy import origin
from penagent_common.store import Store
from executor.service import Executor, public_result
from interpreter.service import Interpreter
from report.synth import build_report

TARGETS = {
    "juice-shop": {"url": "http://127.0.0.1:18001", "method": "GET", "path": "/"},
    "srebench": {"url": "http://127.0.0.1:18002", "method": "GET", "path": "/health"},
    "dvws": {"url": "http://127.0.0.1:18003", "method": "GET", "path": "/api/v1/debug/env",
        # A real information-disclosure endpoint on this live target: no auth
        # required, and it returns DB credentials and a JWT signing secret.
        "expectation": Expectation(expected_behavior="Anonymous clients must not receive internal credentials or signing secrets",
            protected_fields=["DATABASE_URL", "JWT_SECRET"])},
}


def build_settings(directory, name, url, operations):
    return Settings(database=str(Path(directory) / f"{name}.db"), encryption_key=Fernet.generate_key().decode(),
        service_token=secrets.token_urlsafe(32), api_tokens={"operator": secrets.token_urlsafe(32)},
        targets={name: TargetPolicy(base_url=url, operations=operations)})


async def smoke_one(directory, target_id, config):
    origin(config["url"])  # the same numeric-origin safety check C3 itself enforces
    node = EndpointNode(id=f"op_{target_id.replace('-', '_')}", method=config["method"], path=config["path"])
    graph = EndpointGraph(target_id=target_id, graph_id="operator-scope", spec_hash="operator-authorized-smoke-check",
        created_at="verification", updated_at="verification", nodes=[node])
    hypothesis = AttackHypothesis(id=f"{target_id}-smoke", target_endpoints=[node.id], owasp_category="API8:Security_Misconfiguration",
        attack_sequence=[AttackSequenceStep(step=1, op=node.id)])
    operation = OperationPolicy(method=config["method"], path=config["path"], expectation=config.get("expectation"))
    settings = build_settings(directory, target_id, config["url"], {node.id: operation})
    store = Store(settings)
    audit = f"{target_id}-smoke"
    store.create(audit, "operator", target_id)
    executor = Executor(settings, store)
    result = await executor.execute(audit, "operator", hypothesis, Probe(hypothesis_id=hypothesis.id, op=node.id), "smoke-" + target_id, graph)
    assert result.status == "executed", (target_id, result.error)
    interpretation = await Interpreter(settings, store).interpret(audit, "operator", result.probe_id)
    report = build_report(audit, target_id, store.trace(audit, "operator"), settings.targets)
    return {"target": target_id, "url": config["url"], "path": config["path"], "status_code": result.status_code,
        "classification": interpretation.classification.value, "report_summary": report.summary,
        "result": public_result(result)}


async def dvws_approval_gate(directory):
    """Component 5: a genuinely destructive real op on this live target (DELETE
    purge-cache -- confirmed live to actually purge something, not a mock) must
    pause for approval rather than execute outright. Demonstrated with one
    explicit approve and one explicit deny, on separate audits of the same
    target so neither replays the other's reservation."""
    url = TARGETS["dvws"]["url"]
    node = EndpointNode(id="op_dvws_purge_cache", method="DELETE", path="/api/v1/admin/maintenance/purge-cache")
    graph = EndpointGraph(target_id="dvws-gate", graph_id="operator-scope", spec_hash="operator-authorized-smoke-check",
        created_at="verification", updated_at="verification", nodes=[node])
    hypothesis = AttackHypothesis(id="dvws-purge-check", target_endpoints=[node.id], owasp_category="API8:Security_Misconfiguration",
        attack_sequence=[AttackSequenceStep(step=1, op=node.id)])
    settings = build_settings(directory, "dvws-gate", url, {node.id: OperationPolicy(method="DELETE", path=node.path)})
    store = Store(settings)
    executor = Executor(settings, store)
    outcomes = {}
    for decision in ("approve", "deny"):
        audit = f"dvws-gate-{decision}"
        store.create(audit, "operator", "dvws-gate")
        pending = await executor.execute(audit, "operator", hypothesis, Probe(hypothesis_id=hypothesis.id, op=node.id), "gate-" + decision, graph)
        assert pending.status == "awaiting_approval", pending
        store.decide_approval(audit, "operator", pending.probe_id, "approved" if decision == "approve" else "denied",
                               "verification: exercising the " + decision + " path", "operator")
        if decision == "approve":
            final = await executor.execute_approved(audit, "operator", pending.probe_id, "gate-approve-replay")
        else:
            final = executor.execute_denied(audit, "operator", pending.probe_id, "verification: exercising the deny path")
        outcomes[decision] = public_result(final)
    return outcomes


async def run():
    with tempfile.TemporaryDirectory(prefix="penagent-testenv-") as directory:
        results = {target_id: await smoke_one(directory, target_id, config) for target_id, config in TARGETS.items()}
        results["dvws_approval_gate"] = await dvws_approval_gate(directory)
        return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/testenv-verify.json")
    args = parser.parse_args()
    result = asyncio.run(run())
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"status": "PASSED",
        "targets": {k: v["classification"] for k, v in result.items() if k != "dvws_approval_gate"},
        "approval_gate": {k: v["status"] for k, v in result["dvws_approval_gate"].items()}}))


if __name__ == "__main__":
    main()
