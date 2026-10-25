import pytest
from sis.models import ParameterModel, AuthInfo
from executor.service import Executor
from interpreter.service import Interpreter
from penagent_common.models import StateWrite
from penagent_common.policy import Rejected
from test_executor import transport


async def observation(settings, store, graph, hypothesis, probe, body):
    ex = Executor(settings, store, transport(body=body))
    result = await ex.execute("audit", "alice", hypothesis, probe, "c", graph)
    assert result.status == "executed", result
    service = Interpreter(settings, store)
    await service.interpret("audit", "alice", result.probe_id)
    return ex, service, result


async def test_parameter_boundaries_depend_on_observed_field(settings, store, graph, hypothesis, probe):
    graph.nodes[0].parameters = [ParameterModel(name="limit", location="query", schema_raw={"type": "integer", "minimum": 1, "maximum": 3})]
    probe.binding.query = {"limit": 2}
    ex, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","invalid_parameter":"limit"}')
    mutation = await service.mutate("audit", "alice", result.probe_id)
    assert mutation.probe.binding.query == {"limit": 1}
    revised = await ex.execute("audit", "alice", hypothesis, mutation.probe, "c", graph)
    await service.interpret("audit", "alice", revised.probe_id)
    next_mutation = await service.mutate("audit", "alice", revised.probe_id)
    assert next_mutation.probe.binding.query == {"limit": 3}


async def test_auth_context_comparison_reuses_only_approved_state(settings, store, graph, hypothesis, probe):
    graph.nodes[0].auth = AuthInfo(type="bearer")
    rule = settings.targets["fixture"].operations["op_read"]
    rule.auth_context_variations = ["unapproved", "approved"]
    store.write("audit", "alice", StateWrite(category="tokens", key="approved", value="synthetic-approved-token"))
    _, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","compare_auth_context":true}')
    mutation = await service.mutate("audit", "alice", result.probe_id)
    assert mutation.probe.binding.session_ref == "approved"


async def test_auth_comparison_missing_session_returns_no_proposal(settings, store, graph, hypothesis, probe):
    settings.targets["fixture"].operations["op_read"].auth_context_variations = ["approved"]
    _, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","compare_auth_context":true}')
    assert await service.mutate("audit", "alice", result.probe_id) is None


async def test_identifier_reuse_is_observed_and_schema_valid(settings, store, graph, hypothesis, probe):
    graph.nodes[0].parameters = [ParameterModel(name="object_id", location="query", schema_raw={"type": "string"})]
    ex, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","missing_parameter":"object_id","object_id":"observed-object"}')
    mutation = await service.mutate("audit", "alice", result.probe_id)
    assert mutation.probe.binding.query == {"object_id": {"$state": "object_ids.op_read.object_id"}}
    revised = await ex.execute("audit", "alice", hypothesis, mutation.probe, "c", graph)
    assert revised.status == "executed"


async def test_maximum_depth_terminates(settings, store, graph, hypothesis, probe):
    settings.max_depth = 1
    _, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","missing_header":"X-Test-Context"}')
    with pytest.raises(Rejected, match="mutation_budget_exhausted"):
        await service.mutate("audit", "alice", result.probe_id)


async def test_unsafe_header_value_rejected_before_network(settings, store, graph, hypothesis, probe):
    ex, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","missing_header":"X-Test-Context"}')
    mutation = await service.mutate("audit", "alice", result.probe_id)
    mutation.probe.binding.headers["X-Test-Context"] = "not-approved"
    response = await ex.execute("audit", "alice", hypothesis, mutation.probe, "c", graph)
    assert response.error == "mutation_header_value_not_authorized" and response.attempts == 0


async def test_unrelated_observation_does_not_replay_variations(settings, store, graph, hypothesis, probe):
    graph.nodes[0].parameters = [ParameterModel(name="limit", location="query", schema_raw={"type": "integer", "minimum": 1, "maximum": 3})]
    _, service, result = await observation(settings, store, graph, hypothesis, probe, b'{"signal":"x","invalid_parameter":"unknown"}')
    assert await service.mutate("audit", "alice", result.probe_id) is None
