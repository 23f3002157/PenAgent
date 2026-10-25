"""Component 6: audit report generation from stored C3/C4 evidence."""
import httpx
import pytest
from fastapi.testclient import TestClient

from executor.service import Executor
from penagent_common.models import Binding, Interpretation, Probe
from report.cvss import base_score, severity
from report.main import create_app
from report.synth import _remediation, build_report


class Bytes(httpx.AsyncByteStream):
    def __init__(self, value):
        self.value = value
    async def __aiter__(self):
        yield self.value


def transport(code=200, body=b'{"object_id":"obj-1"}'):
    return httpx.MockTransport(lambda request: httpx.Response(code, headers={"content-type": "application/json"}, stream=Bytes(body)))


def interp(classification, probe_id, hyp_id, **kw):
    defaults = dict(audit_id="audit", hypothesis_id=hyp_id, probe_id=probe_id, classification=classification,
        confidence=.5, evidence_refs=[probe_id], observed_behavior="HTTP 200", expected_behavior="n/a",
        reasoning_summary="synthetic test interpretation", next_action="next_hypothesis")
    defaults.update(kw)
    return Interpretation(**defaults)


@pytest.fixture
async def seeded_trace(settings, store, graph, hypothesis):
    """Five probes, one classification each, including a STRONG->CONFIRMED mutation
    chain so chain reconstruction and request_summary ordering can be checked."""
    ex = Executor(settings, store, transport())

    def probe(context, **kw):
        return Probe(hypothesis_id=hypothesis.id, op="op_read", binding=Binding(headers={"X-Test-Context": context}), **kw)

    root = await ex.execute("audit", "alice", hypothesis, probe("strong"), "c1", graph)
    store.interpretation("audit", root.probe_id, interp("STRONG_SIGNAL", root.probe_id, hypothesis.id, next_action="mutate"))

    child = probe("fixture-only", parent_probe_id=root.probe_id, depth=1)
    confirmed = await ex.execute("audit", "alice", hypothesis, child, "c2", graph)
    store.interpretation("audit", confirmed.probe_id, interp("CONFIRMED_VULNERABILITY", confirmed.probe_id, hypothesis.id, confidence=.98, next_action="replan", replan_justified=True))

    weak = await ex.execute("audit", "alice", hypothesis, probe("weak"), "c3", graph)
    store.interpretation("audit", weak.probe_id, interp("WEAK_SIGNAL", weak.probe_id, hypothesis.id))

    negative = await ex.execute("audit", "alice", hypothesis, probe("negative"), "c4", graph)
    store.interpretation("audit", negative.probe_id, interp("NEGATIVE", negative.probe_id, hypothesis.id))

    crash = await ex.execute("audit", "alice", hypothesis, probe("crash"), "c5", graph)
    store.interpretation("audit", crash.probe_id, interp("ERROR_CRASH", crash.probe_id, hypothesis.id, confidence=.95, next_action="stop"))

    trace = store.trace("audit", "alice")
    return trace, root.probe_id, confirmed.probe_id, weak.probe_id, negative.probe_id, crash.probe_id


async def test_report_buckets_each_classification(settings, seeded_trace):
    trace, root_id, confirmed_id, weak_id, negative_id, crash_id = seeded_trace
    report = build_report("audit", "fixture", trace, settings.targets)
    assert report.probes_executed == 5
    assert report.summary == {"STRONG_SIGNAL": 1, "CONFIRMED_VULNERABILITY": 1, "WEAK_SIGNAL": 1, "NEGATIVE": 1, "ERROR_CRASH": 1}
    # NEGATIVE contributes nothing; WEAK_SIGNAL/ERROR_CRASH are unscored buckets.
    assert {f.classification.value for f in report.findings} == {"STRONG_SIGNAL", "CONFIRMED_VULNERABILITY"}
    assert len(report.observations) == 1 and report.observations[0]["probe_id"] == weak_id
    assert len(report.operational_issues) == 1 and report.operational_issues[0]["probe_id"] == crash_id
    assert not any(o["probe_id"] == negative_id for o in report.observations + report.operational_issues)


async def test_confirmed_finding_chain_and_cvss(settings, seeded_trace):
    trace, root_id, confirmed_id, *_ = seeded_trace
    report = build_report("audit", "fixture", trace, settings.targets)
    confirmed = next(f for f in report.findings if f.classification.value == "CONFIRMED_VULNERABILITY")
    assert confirmed.probe_chain == [root_id, confirmed_id]
    assert [r["probe_id"] for r in confirmed.request_summary] == [root_id, confirmed_id]
    assert confirmed.cvss_vector.startswith("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/")  # chain of 2 -> AC:H
    assert 0 < confirmed.cvss_score <= 10
    assert confirmed.severity == severity(confirmed.cvss_score)
    assert confirmed.owasp_category == "API5:BFLA"
    assert "fixture-secret" not in str(confirmed.request_summary)  # never raw credentials/body text

    strong = next(f for f in report.findings if f.classification.value == "STRONG_SIGNAL")
    assert strong.probe_chain == [root_id]
    assert strong.cvss_vector.startswith("CVSS:3.1/AV:N/AC:L/")  # root probe -> AC:L


def test_remediation_lookup_hits_known_category_and_falls_back():
    assert "object-level authorization" in _remediation("API1:BOLA")
    assert _remediation("Unmapped:Category") != ""
    assert _remediation("Unmapped:Category") == _remediation("totally-unknown")


async def test_report_http_endpoint(settings, seeded_trace):
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get("/v1/audits/audit/report", headers={"Authorization": "Bearer alice-test-only"})
        assert response.status_code == 200
        body = response.json()
        assert body["audit_id"] == "audit" and body["probes_executed"] == 5
        assert {f["classification"] for f in body["findings"]} == {"STRONG_SIGNAL", "CONFIRMED_VULNERABILITY"}
        # Bob never created this audit and cannot read its report.
        assert client.get("/v1/audits/audit/report", headers={"Authorization": "Bearer bob-test-only"}).status_code == 404
        assert client.get("/v1/audits/audit/report").status_code == 401


def test_cvss_reference_vectors():
    _, perfect = base_score("N", "L", "N", "N", "U", "H", "H", "H")
    assert perfect == 9.8
    _, changed_scope = base_score("N", "L", "N", "N", "C", "H", "H", "H")
    assert changed_scope == 10.0
    assert severity(9.8) == "critical" and severity(7.0) == "high" and severity(4.0) == "medium" and severity(1.0) == "low"
