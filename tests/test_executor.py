import asyncio
import json
import sqlite3
import httpx
import pytest
from pydantic import ValidationError

from executor.parser import parse_response
from executor.service import Executor, public_result
from executor.tools import Tools
from executor.validation import build_arguments
from penagent_common.models import HTTPArguments, StateWrite, Binding, Probe, ExecutionResult
from penagent_common.policy import Rejected, origin, enforce_url
from penagent_common.store import Store


class Bytes(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = value
    async def __aiter__(self):
        yield self.value


def transport(code=200, body=b'{"object_id":"obj-1"}', headers=None):
    return httpx.MockTransport(lambda request: httpx.Response(code, headers=headers or {"content-type": "application/json"}, stream=Bytes(body)))


async def execute(settings, store, graph, hypothesis, probe, **kw):
    executor = Executor(settings, store, kw.pop("transport", transport()))
    return await executor.execute("audit", "alice", hypothesis, probe, "corr-1", graph)


async def test_valid_request(settings, store, graph, hypothesis, probe):
    result = await execute(settings, store, graph, hypothesis, probe)
    assert result.status == "executed" and result.status_code == 200 and result.attempts == 1
    assert result.correlation_id == "corr-1"
    ExecutionResult.model_validate(public_result(result))
    assert store.read("audit", "alice").values["object_ids"]["op_read.object_id"] == "obj-1"
    assert store.get_probe("audit", "alice", result.probe_id)["result"]["latency_ms"] >= 0


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "get", "BOGUS"])
def test_invalid_method(method):
    with pytest.raises(ValidationError):
        HTTPArguments(method=method, url="http://127.0.0.1/")


@pytest.mark.parametrize("url", ["file:///tmp/a", "http://metadata.google.internal/", "http://169.254.169.254/latest", "http://100.100.100.200/", "http://168.63.129.16/", "http://127.0.0.1@169.254.169.254/", "http://127.0.0.1/#a", "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "http://127.0.0.1:bad/", "http://localhost/", "https://example.com/"])
def test_invalid_url(url):
    with pytest.raises(Rejected):
        origin(url)


def test_unauthorized_destination(settings):
    with pytest.raises(Rejected):
        enforce_url("http://127.0.0.1:9999/admin/object", settings.targets["fixture"])


async def test_unsafe_redirect(settings, store, graph, hypothesis, probe):
    result = await execute(settings, store, graph, hypothesis, probe, transport=transport(302, b"", {"location": "http://169.254.169.254/latest"}))
    assert result.status == "blocked" and result.attempts == 1
    assert "origin" in result.error


async def test_same_origin_redirect_denied(settings, store, graph, hypothesis, probe):
    result = await execute(settings, store, graph, hypothesis, probe, transport=transport(302, b"", {"location": "/other"}))
    assert result.error == "redirect_not_followed"


@pytest.mark.parametrize("body,ct,kind", [(b'{"object_id":"x"}', "application/json", "json"), (b'{broken', "application/json", "malformed"), (b'', "application/json", "empty"), (b'hello', "text/plain", "text"), (b'\x00', "image/png", "binary"), (b'NaN', "application/json", "malformed")])
def test_parse_variants(node, body, ct, kind):
    parsed = parse_response(body, ct, node, 200, [])
    assert parsed.kind == kind and len(parsed.body_sha256) == 64


def test_schema_aware_credentials(node):
    parsed = parse_response(b'{"access_token":"valid-fixture-token","arbitrary":"looks-like-token","object_id":"obj"}', "application/json", node, 200, ["access_token", "arbitrary"])
    assert parsed.credential_fields == ["access_token"]
    assert "arbitrary" not in parsed.artifacts
    assert not parse_response(b'{"access_token":"short"}', "application/json", node, 200, ["access_token"]).credential_fields
    assert not parse_response(b'{"object_id":"error-id"}', "application/json", node, 403, []).artifacts


@pytest.mark.parametrize("code", [400, 401, 403, 404, 500, 503])
async def test_http_errors_are_responses(settings, store, graph, hypothesis, probe, code):
    result = await execute(settings, store, graph, hypothesis, probe, transport=transport(code))
    assert result.status == "executed" and result.status_code == code and result.attempts == 1
    if code >= 500:
        assert store.audit("audit", "alice")["halted"] == 1


@pytest.mark.parametrize("failure,error", [(httpx.ConnectError, "transport_failure"), (httpx.ReadTimeout, "transport_timeout_not_proof_of_crash"), (httpx.RemoteProtocolError, "transport_failure")])
async def test_network_errors(settings, store, graph, hypothesis, probe, failure, error):
    count = 0
    def handler(request):
        nonlocal count
        count += 1
        raise failure("synthetic sensitive server message")
    result = await execute(settings, store, graph, hypothesis, probe, transport=httpx.MockTransport(handler))
    assert result.status == "error" and result.error == error
    assert count == (settings.retries + 1 if failure is httpx.ConnectError else 1)


async def test_retry_never_post(settings, store, graph, hypothesis, probe):
    graph.nodes[0].method = "POST"
    settings.targets["fixture"].operations["op_read"].method = "POST"
    def handler(request):
        raise httpx.ConnectError("refused")
    result = await execute(settings, store, graph, hypothesis, probe, transport=httpx.MockTransport(handler))
    assert result.attempts == 1


async def test_oversized_response(settings, store, graph, hypothesis, probe):
    settings.max_response_size = 5
    result = await execute(settings, store, graph, hypothesis, probe)
    assert result.error == "response_too_large" and result.status == "blocked"


async def test_encoded_response(settings, store, graph, hypothesis, probe):
    result = await execute(settings, store, graph, hypothesis, probe, transport=transport(headers={"content-encoding": "gzip"}))
    assert result.error == "encoded_response_not_supported"


@pytest.mark.parametrize("headers", [{"Host": "other"}, {"Authorization": "secret"}, {"X-Test": "a\r\nb"}, {"Bad Header": "x"}])
def test_invalid_headers(headers):
    with pytest.raises(ValidationError):
        HTTPArguments(method="GET", url="http://127.0.0.1/", headers=headers)


def test_state_isolation_persistence_encryption(settings, store):
    secret = "fixture-credential-not-real"
    store.write("audit", "alice", StateWrite(category="tokens", key="approved", value=secret))
    store.write("audit", "alice", StateWrite(category="object_ids", key="id", value="obj"))
    assert secret not in str(store.read("audit", "alice"))
    with pytest.raises(Rejected):
        store.read("audit", "bob", secrets=True)
    with pytest.raises(Rejected):
        store.write("audit", "bob", StateWrite(category="tokens", key="approved", value="x"))
    fresh = Store(settings)
    assert fresh.read("audit", "alice", secrets=True).values["tokens"]["approved"] == secret
    assert secret.encode() not in open(settings.database, "rb").read()
    assert fresh.read("audit", "alice").values["object_ids"]["id"] == "obj"


async def test_secret_redaction(settings, store, graph, hypothesis, probe, caplog):
    result = await execute(settings, store, graph, hypothesis, probe, transport=transport(body=b'{"access_token":"fixture-secret-token","private_data":"sensitive free text"}'))
    assert "fixture-secret-token" not in str(public_result(result))
    assert "sensitive free text" not in str(public_result(result))
    assert "fixture-secret-token" not in caplog.text
    assert store.read("audit", "alice", secrets=True).values["tokens"]["op_read.access_token"] == "fixture-secret-token"


@pytest.mark.parametrize("method,path", [("DELETE", "/admin/object"), ("GET", "/reset-account"), ("POST", "/payment/charge")])
async def test_approval_denied_by_semantics(settings, store, graph, hypothesis, probe, method, path):
    graph.nodes[0].method, graph.nodes[0].path = method, path
    rule = settings.targets["fixture"].operations["op_read"]
    rule.method, rule.path = method, path
    result = await execute(settings, store, graph, hypothesis, probe)
    assert result.approval_required and result.attempts == 0
    assert store.audit("audit", "alice")["state"] == "AWAITING_APPROVAL"


async def test_hallucinated_endpoint(settings, store, graph, hypothesis, probe):
    hypothesis.target_endpoints = ["invented"]
    result = await execute(settings, store, graph, hypothesis, probe)
    assert result.error == "hallucinated_endpoint" and result.attempts == 0


async def test_missing_context(settings, store, graph, hypothesis, probe):
    probe.binding.session_ref = "approved"
    result = await execute(settings, store, graph, hypothesis, probe)
    assert result.error == "missing_session_context" and result.attempts == 0


async def test_duplicate_and_budget(settings, store, graph, hypothesis, probe):
    first = await execute(settings, store, graph, hypothesis, probe)
    second = await execute(settings, store, graph, hypothesis, probe)
    assert first.status == "executed" and second.status == "duplicate" and second.attempts == 0
    settings.max_probes = 1
    probe.binding.headers = {"X-Test-Context": "fixture-only"}
    third = await execute(settings, store, graph, hypothesis, probe)
    assert third.status == "budget_exhausted"


async def test_cancel_before_send(settings, store, graph, hypothesis, probe):
    store.cancel("audit", "alice")
    result = await execute(settings, store, graph, hypothesis, probe)
    assert result.status == "cancelled" and result.attempts == 0


async def test_strict_tool_arguments(settings, store, hypothesis, probe):
    tools = Tools(Executor(settings, store), "audit", "alice", hypothesis, probe, "corr")
    for name, args in [("http_request", {"method": "TRACE", "url": "x"}), ("read_session_state", {"audit_id": "other"}), ("unknown", {}), ("write_session_state", {"category": "tokens", "key": "fake", "value": "invented"})]:
        assert (await tools.invoke(name, args))["status"] == "blocked"
    assert (await tools.invoke("read_session_state", {}))["audit_id"] == "audit"
    await tools.invoke("write_session_state", {"category": "observations", "key": "note", "value": "observation"})
    assert "note" in store.read("audit", "alice").values["observations"]
    assert {d["function"]["name"] for d in Tools.definitions()} == set(Tools.schemas)
