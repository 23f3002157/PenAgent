import pytest
from executor.service import Executor
from interpreter.evidence import interpret
from interpreter.service import Interpreter
from penagent_common.models import Category, ExecutionResult, Parsed, Probe
from penagent_common.policy import Rejected
from test_executor import transport


@pytest.mark.parametrize("code,data,expected", [
    (200, {"owner": "tenant-b", "private_data": "simulated"}, Category.CONFIRMED_VULNERABILITY),
    (200, {"signal": "restricted-object", "missing_header": "X-Test-Context"}, Category.STRONG_SIGNAL),
    (200, {"message": "ok"}, Category.WEAK_SIGNAL),
    (403, {"message": "denied"}, Category.NEGATIVE),
    (403, {"private_data": "unexpected disclosure"}, Category.STRONG_SIGNAL),
    (500, {"message": "error"}, Category.ERROR_CRASH),
    (200, {"owner": "tenant-a", "message": "ordinary success"}, Category.WEAK_SIGNAL)])
def test_five_classifications(settings, hypothesis, probe, code, data, expected):
    result = ExecutionResult(audit_id="audit", hypothesis_id="h1", probe_id="p", correlation_id="c", op="op_read", status="executed", status_code=code,
                             parsed=Parsed(kind="json", data=data, body_sha256="hash"))
    output = interpret(result, hypothesis, probe, settings.targets["fixture"].operations["op_read"])
    assert output.classification == expected
    assert output.evidence_refs == ["p", "hash"]
    if code >= 500:
        assert output.next_action == "stop" and "unproven" in output.reasoning_summary


def test_timeout_not_crash(settings, hypothesis, probe):
    result = ExecutionResult(audit_id="audit", hypothesis_id="h1", correlation_id="c", op="op_read", status="error", error="transport_timeout_not_proof_of_crash")
    output = interpret(result, hypothesis, probe, settings.targets["fixture"].operations["op_read"])
    assert output.classification == Category.ERROR_CRASH
    assert "not evidence of a crash" in output.reasoning_summary


async def strong(settings, store, graph, hypothesis, probe):
    ex = Executor(settings, store, transport(body=b'{"signal":"restricted","missing_header":"X-Test-Context"}'))
    result = await ex.execute("audit", "alice", hypothesis, probe, "c", graph)
    service = Interpreter(settings, store)
    output = await service.interpret("audit", "alice", result.probe_id)
    assert output.classification == Category.STRONG_SIGNAL
    return ex, service, result, output


async def test_valid_mutation_and_duplicate(settings, store, graph, hypothesis, probe):
    ex, service, result, _ = await strong(settings, store, graph, hypothesis, probe)
    mutation = await service.mutate("audit", "alice", result.probe_id)
    assert mutation.probe.binding.headers == {"X-Test-Context": "fixture-only"}
    assert mutation.original_hypothesis_id == hypothesis.id and mutation.observation_id == result.probe_id
    revised = await ex.execute("audit", "alice", hypothesis, mutation.probe, "c", graph)
    await service.interpret("audit", "alice", revised.probe_id)
    assert await service.mutate("audit", "alice", revised.probe_id) is None
    again = await ex.execute("audit", "alice", hypothesis, mutation.probe, "c", graph)
    assert again.status == "duplicate"


async def test_invalid_mutation_parent(settings, store, graph, hypothesis, probe):
    ex, service, result, _ = await strong(settings, store, graph, hypothesis, probe)
    mutation = await service.mutate("audit", "alice", result.probe_id)
    mutation.probe.depth = 0
    response = await ex.execute("audit", "alice", hypothesis, mutation.probe, "c", graph)
    assert response.error == "invalid_mutation_parent"


async def test_mutation_budget_exhausted(settings, store, graph, hypothesis, probe):
    ex, service, result, _ = await strong(settings, store, graph, hypothesis, probe)
    settings.max_mutations = 0
    with pytest.raises(Rejected, match="mutation_budget_exhausted"):
        await service.mutate("audit", "alice", result.probe_id)


async def test_no_progress_termination(settings, store, graph, hypothesis, probe):
    _, service, result, _ = await strong(settings, store, graph, hypothesis, probe)
    settings.targets["fixture"].operations["op_read"].header_variations = {}
    assert await service.mutate("audit", "alice", result.probe_id) is None
    assert any(e["kind"] == "no_progress" for e in store.trace("audit", "alice")["events"])


async def test_replanning_trigger(settings, store, graph, hypothesis, probe):
    ex = Executor(settings, store, transport(body=b'{"owner":"tenant-b","private_data":"SIMULATED"}'))
    result = await ex.execute("audit", "alice", hypothesis, probe, "c", graph)
    output = await Interpreter(settings, store).interpret("audit", "alice", result.probe_id)
    assert output.replan_justified and output.next_action == "replan"


@pytest.mark.parametrize("failure", ["malformed", "unavailable"])
async def test_llm_failure_preserves_evidence(settings, store, graph, hypothesis, probe, failure):
    ex = Executor(settings, store, transport(body=b'{"signal":"restricted"}'))
    result = await ex.execute("audit", "alice", hypothesis, probe, "c", graph)
    class BadProvider:
        async def recommend(self, summary):
            assert "restricted" not in str(summary)
            raise Rejected("llm_" + failure)
    settings.llm_url = "http://127.0.0.1:18766"
    output = await Interpreter(settings, store, BadProvider()).interpret("audit", "alice", result.probe_id)
    assert output.next_action == "preserve" and output.error == "llm_" + failure
    assert store.audit("audit", "alice")["llm_calls"] == 1


async def test_llm_budget(settings, store, graph, hypothesis, probe):
    ex = Executor(settings, store, transport(body=b'{"signal":"restricted"}'))
    result = await ex.execute("audit", "alice", hypothesis, probe, "c", graph)
    settings.llm_url, settings.max_llm_calls = "http://127.0.0.1:18766", 0
    output = await Interpreter(settings, store).interpret("audit", "alice", result.probe_id)
    assert output.error == "llm_budget_exhausted"
