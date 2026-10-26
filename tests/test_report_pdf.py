"""Component 6: the actual PDF output, not an out-of-band script."""
from report.pdf import build_pdf
from penagent_common.models import AuditReport, Finding


def make_report(findings=None, observations=None, operational_issues=None):
    return AuditReport(audit_id="pdf-test", target_id="fixture", generated_at=1_700_000_000.0,
        probes_executed=3, findings=findings or [], observations=observations or [],
        operational_issues=operational_issues or [], summary={"CONFIRMED_VULNERABILITY": len(findings or [])})


def make_finding(**overrides):
    base = dict(finding_id="f1", title="API1:2023 - Broken Object Level Authorization on GET /accounts/{id}",
        owasp_category="API1:2023 - Broken Object Level Authorization", classification="CONFIRMED_VULNERABILITY",
        confidence=0.98, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_score=7.5, severity="high",
        probe_chain=["p1"], request_summary=[], explanation="Configured forbidden value observed.",
        remediation="Enforce object-level authorization server-side.")
    base.update(overrides)
    return Finding(**base)


def test_build_pdf_with_findings_produces_a_real_pdf():
    report = make_report(findings=[make_finding()])
    pdf_bytes = build_pdf(report)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


def test_build_pdf_handles_empty_report():
    report = make_report()
    pdf_bytes = build_pdf(report)
    assert pdf_bytes.startswith(b"%PDF-")


def test_build_pdf_with_observations_and_operational_issues():
    report = make_report(
        observations=[{"method": "GET", "path": "/x", "owasp_category": "API8:2023 - Security Misconfiguration", "reasoning_summary": "Unusual but inconclusive."}],
        operational_issues=[{"method": "GET", "path": "/y", "reasoning_summary": "Server returned 500."}],
    )
    pdf_bytes = build_pdf(report)
    assert pdf_bytes.startswith(b"%PDF-")


def test_build_pdf_never_contains_raw_request_summary_secrets():
    # request_summary entries are already public_result()-shaped upstream; a
    # stray raw secret slipping in here must not render into the PDF text.
    finding = make_finding(request_summary=[{"parsed": {"data": {"evidence_available": True, "body_sha256": "abc123"}}}])
    pdf_bytes = build_pdf(make_report(findings=[finding]))
    assert b"abc123" not in pdf_bytes  # request_summary isn't rendered into the PDF body at all
