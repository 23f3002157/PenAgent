import sys
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from sis.models import EndpointGraph, EndpointNode
from hgs.models import AttackHypothesis, AttackSequenceStep
from penagent_common.config import Settings, TargetPolicy, OperationPolicy, Expectation
from penagent_common.models import Probe
from penagent_common.store import Store

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def node():
    return EndpointNode(id="op_read", method="GET", path="/admin/object", response_schemas={"200": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"object_id": {"type": "string"}, "access_token": {"type": "string"},
        "owner": {"type": "string"}, "private_data": {"type": "string"}, "signal": {"type": "string"}, "missing_header": {"type": "string"}}}}}}})


@pytest.fixture
def graph(node):
    return EndpointGraph(target_id="fixture", graph_id="graph_fixture", spec_hash="abc", nodes=[node], created_at="now", updated_at="now")


@pytest.fixture
def hypothesis():
    return AttackHypothesis(id="h1", target_endpoints=["op_read"], owasp_category="API5:BFLA", attack_sequence=[AttackSequenceStep(step=1, op="op_read", method="GET", path="/admin/object")])


@pytest.fixture
def probe():
    return Probe(hypothesis_id="h1", op="op_read")


@pytest.fixture
def settings(tmp_path):
    return Settings(database=str(tmp_path / "state.db"), encryption_key=Fernet.generate_key().decode(), service_token="machine-test-only",
        api_tokens={"alice": "alice-test-only", "bob": "bob-test-only"}, requests_per_second=100.0,
        targets={"fixture": TargetPolicy(base_url="http://127.0.0.1:18765", credential_refs=["approved"], operations={"op_read": OperationPolicy(method="GET", path="/admin/object",
            allowed_headers=["X-Test-Context"], header_variations={"X-Test-Context": ["fixture-only"]}, response_credentials=["access_token"],
            expectation=Expectation(expected_behavior="Anonymous clients must not receive another tenant's private data", protected_fields=["private_data"],
                signal_fields=["signal"], forbidden_values={"owner": "tenant-b"}))})})


@pytest.fixture
def store(settings):
    store = Store(settings)
    store.create("audit", "alice", "fixture")
    return store
