"""Component 5: human approval gate for destructive/non-safe operations."""
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from executor.main import create_app
from executor.service import Executor
from penagent_common.models import Probe
from penagent_common.policy import Rejected


class Bytes(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = value
    async def __aiter__(self):
        yield self.value


def transport(code=200, body=b'{"object_id":"obj-1"}', headers=None):
    return httpx.MockTransport(lambda request: httpx.Response(code, headers=headers or {"content-type": "application/json"}, stream=Bytes(body)))


def make_destructive(settings):
    """Reuse conftest's authorized safe fixture op but mark it destructive, so the
    approval gate is exercised without a second live route."""
    rule = settings.targets["fixture"].operations["op_read"]
    rule.risk = "destructive"
    return rule


async def test_destructive_op_becomes_pending(settings, store, graph, hypothesis, probe):
    make_destructive(settings)
    ex = Executor(settings, store, transport())
    result = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    assert result.status == "awaiting_approval" and result.attempts == 0 and result.approval_required
    assert store.audit("audit", "alice")["state"] == "AWAITING_APPROVAL"
    pending = store.approvals("audit", "alice", pending_only=True)
    assert len(pending) == 1 and pending[0]["probe_id"] == result.probe_id
    assert pending[0]["status"] == "pending"
    assert pending[0]["description"]["method"] == "GET" and pending[0]["description"]["path"] == "/admin/object"
    assert pending[0]["description"]["risk_classification"] == "destructive"


async def test_approve_executes_for_real(settings, store, graph, hypothesis, probe):
    make_destructive(settings)
    ex = Executor(settings, store, transport())
    pending = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    store.decide_approval("audit", "alice", pending.probe_id, "approved", None, "alice")
    executed = await ex.execute_approved("audit", "alice", pending.probe_id, "corr-2")
    assert executed.status == "executed" and executed.status_code == 200 and executed.attempts == 1
    assert executed.correlation_id == "corr-2"
    stored = store.get_probe("audit", "alice", pending.probe_id)
    assert stored["result"]["status"] == "executed"
    assert store.approvals("audit", "alice")[0]["status"] == "approved"


async def test_deny_blocks_permanently(settings, store, graph, hypothesis, probe):
    make_destructive(settings)
    ex = Executor(settings, store, transport())
    pending = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    store.decide_approval("audit", "alice", pending.probe_id, "denied", "too risky", "alice")
    denied = ex.execute_denied("audit", "alice", pending.probe_id, "too risky")
    assert denied.status == "blocked" and denied.error == "too risky" and denied.attempts == 0
    assert store.approvals("audit", "alice")[0]["status"] == "denied"


async def test_double_decide_rejected(settings, store, graph, hypothesis, probe):
    make_destructive(settings)
    ex = Executor(settings, store, transport())
    pending = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    store.decide_approval("audit", "alice", pending.probe_id, "denied", None, "alice")
    with pytest.raises(Rejected, match="approval_already_decided"):
        store.decide_approval("audit", "alice", pending.probe_id, "approved", None, "alice")


def test_decide_unknown_probe(store):
    with pytest.raises(Rejected, match="approval_not_found"):
        store.decide_approval("audit", "alice", "nope", "approved", None, "alice")


async def test_timeout_auto_skips(settings, store, graph, hypothesis, probe):
    make_destructive(settings)
    settings.approval_timeout = 0.01
    ex = Executor(settings, store, transport())
    pending = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    time.sleep(0.05)
    listed = store.approvals("audit", "alice")
    assert listed[0]["status"] == "timed_out"
    stored = store.get_probe("audit", "alice", pending.probe_id)
    assert stored["result"]["status"] == "blocked"
    assert stored["result"]["error"] == "approval_timed_out_destructive_action_skipped"
    with pytest.raises(Rejected, match="approval_already_decided"):
        store.decide_approval("audit", "alice", pending.probe_id, "approved", None, "alice")


async def test_budget_exhaustion_not_mistaken_for_approval(settings, store, graph, hypothesis, probe):
    make_destructive(settings)
    settings.max_probes = 0
    ex = Executor(settings, store, transport())
    result = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    assert result.status == "budget_exhausted" and not result.approval_required
    assert store.approvals("audit", "alice") == []


async def test_approved_bypass_scoped_to_one_probe(settings, store, graph, hypothesis, probe):
    """Approving one probe must not relax policy for a second, distinct probe."""
    make_destructive(settings)
    ex = Executor(settings, store, transport())
    first = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    store.decide_approval("audit", "alice", first.probe_id, "approved", None, "alice")
    await ex.execute_approved("audit", "alice", first.probe_id, "corr-2")
    second_probe = Probe(hypothesis_id=hypothesis.id, op="op_read", binding={"headers": {"X-Test-Context": "fixture-only"}})
    second = await ex.execute("audit", "alice", hypothesis, second_probe, "corr-3", graph)
    assert second.status == "awaiting_approval"


async def test_approve_rejects_wrong_probe_state(settings, store, graph, hypothesis, probe):
    """execute_approved refuses a probe that was never put on hold (nothing to approve)."""
    ex = Executor(settings, store, transport())
    result = await ex.execute("audit", "alice", hypothesis, probe, "corr-1", graph)
    assert result.status == "executed"
    with pytest.raises(Rejected, match="probe_not_awaiting_approval"):
        await ex.execute_approved("audit", "alice", result.probe_id, "corr-2")


def test_approvals_http_endpoints(settings, graph, hypothesis, probe):
    # Only the approval endpoints are under test here, so the pending probe is
    # seeded directly through the executor (same as the unit tests above) instead
    # of via POST /probes, which would otherwise require a live SIS graph fetch.
    make_destructive(settings)
    app = create_app(settings)
    app.state.executor.transport = transport()
    with TestClient(app) as client:
        alice = {"Authorization": "Bearer alice-test-only"}
        bob = {"Authorization": "Bearer bob-test-only"}
        assert client.post("/v1/audits", json={"audit_id": "a1", "target_id": "fixture", "acknowledged_authorization": True}, headers=alice).status_code == 201
        import asyncio
        pending = asyncio.run(app.state.executor.execute("a1", "alice", hypothesis, probe, "corr-1", graph))
        assert pending.status == "awaiting_approval"
        listing = client.get("/v1/audits/a1/approvals", headers=alice)
        assert listing.status_code == 200 and len(listing.json()["approvals"]) == 1
        assert client.get("/v1/audits/a1/approvals", headers=bob).status_code == 404
        decided = client.post(f"/v1/audits/a1/approvals/{pending.probe_id}", json={"decision": "approve"}, headers=alice)
        assert decided.status_code == 200
        assert decided.json()["status"] == "executed" and decided.json()["status_code"] == 200
        again = client.post(f"/v1/audits/a1/approvals/{pending.probe_id}", json={"decision": "approve"}, headers=alice)
        assert again.status_code == 409
