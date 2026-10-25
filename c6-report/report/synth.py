"""Component 6: assembles stored, already-redacted C3/C4 evidence into a scored
audit report. Pure functions only -- no FastAPI, no network, no LLM. Severity
and classification stay tied to deterministic evidence, matching the principle
already enforced by c4-interpreter/interpreter/evidence.py.
"""
import hashlib
import time

from executor.service import public_result
from penagent_common.models import AuditReport, Finding
from report.cvss import base_score, severity

_REMEDIATION = {
    "API1": "Enforce object-level authorization server-side using the authenticated subject's "
            "own identifier; never trust a client-supplied object ID without an ownership check.",
    "API2": "Strengthen authentication: rotate/revoke any leaked credential, enforce strong token "
            "validation, and remove fallbacks that accept a missing or malformed credential.",
    "API3": "Apply allow-listed, per-property authorization filters on request/response bodies so "
            "clients cannot read or write properties beyond what their role permits.",
    "API4": "Apply resource and rate limits (pagination caps, request quotas, payload size limits) "
            "so a single client cannot exhaust shared resources.",
    "API5": "Enforce function-level authorization checks server-side for every administrative or "
            "privileged operation, independent of client/UI-level hiding.",
    "API6": "Validate business-logic invariants server-side (ownership, state transitions, workflow "
            "order) instead of relying on client-enforced sequencing.",
    "API7": "Treat server-side requests built from user input as untrusted; allow-list destinations "
            "and block internal/metadata address ranges.",
    "API8": "Review configuration for verbose errors, default credentials, unnecessary HTTP methods "
            "and permissive CORS; apply hardened security headers.",
    "API9": "Maintain an accurate inventory of API versions/environments and retire or protect "
            "deprecated and non-production endpoints the same as production ones.",
    "API10": "Validate and sanitize any data consumed from third-party/upstream APIs before trusting "
             "it in business logic.",
}
_REMEDIATION_FALLBACK = ("Review the endpoint's authorization and input-validation logic against the "
                          "observed evidence and the operator's configured security expectation.")


def _remediation(owasp_category: str) -> str:
    upper = (owasp_category or "").upper()
    for prefix, text in _REMEDIATION.items():
        if upper.startswith(prefix):
            return text
    return _REMEDIATION_FALLBACK


def _chain(probes_by_id: dict, probe_id: str) -> list[str]:
    """Walk parent_probe_id back to the root, returning root -> ... -> probe_id."""
    chain, current, seen = [], probe_id, set()
    while current and current not in seen:
        seen.add(current)
        chain.append(current)
        item = probes_by_id.get(current)
        current = item["context"]["probe"].get("parent_probe_id") if item else None
    return list(reversed(chain))


def _impact_metrics(rule) -> tuple[str, str, str]:
    """Confidentiality/Integrity/Availability impact, derived only from the
    operator's own configured policy fields -- never from response content."""
    expectation = getattr(rule, "expectation", None) if rule else None
    protected = len(expectation.protected_fields) if expectation else 0
    c = "H" if protected >= 2 else ("L" if protected == 1 else "N")
    risk = rule.risk if rule else "safe"
    i = {"destructive": "H", "reversible": "L", "safe": "N"}.get(risk, "N")
    a = "N"  # Conservative default: PenAgent does not probe for availability impact.
    return c, i, a


def build_report(audit_id: str, target_id: str, trace: dict, targets: dict) -> AuditReport:
    probes_by_id = {p["probe_id"]: p for p in trace["probes"]}
    target = targets.get(target_id)
    findings, observations, operational_issues, summary = [], [], [], {}

    for item in trace["probes"]:
        interpretation = item["interpretation"]
        if not interpretation:
            continue
        classification = interpretation["classification"]
        summary[classification] = summary.get(classification, 0) + 1
        if classification == "NEGATIVE":
            continue

        probe_ctx = item["context"]["probe"]
        hypothesis = item["context"]["hypothesis"]
        graph = item["context"]["graph"]
        node = next((n for n in graph["nodes"] if n["id"] == probe_ctx["op"]), None)
        rule = target.operations.get(probe_ctx["op"]) if target else None
        method, path = (node["method"], node["path"]) if node else (None, None)

        if classification == "WEAK_SIGNAL":
            observations.append({"probe_id": item["probe_id"], "owasp_category": hypothesis["owasp_category"],
                "method": method, "path": path, "observed_behavior": interpretation["observed_behavior"],
                "reasoning_summary": interpretation["reasoning_summary"]})
            continue
        if classification == "ERROR_CRASH":
            # 5xx/transport failure is a potential logic/availability bug, not proof
            # of a vulnerability -- never scored, matching evidence.py's stance.
            operational_issues.append({"probe_id": item["probe_id"], "owasp_category": hypothesis["owasp_category"],
                "method": method, "path": path, "reasoning_summary": interpretation["reasoning_summary"]})
            continue

        # CONFIRMED_VULNERABILITY or STRONG_SIGNAL: a scored, reproducible finding.
        chain = _chain(probes_by_id, item["probe_id"])
        c, i, a = _impact_metrics(rule)
        ac = "H" if len(chain) > 1 else "L"  # a mutation was needed to confirm
        pr = "L" if probe_ctx["binding"].get("session_ref") else "N"
        vector, score = base_score("N", ac, pr, "N", "U", c, i, a)
        request_summary = [public_result(probes_by_id[pid]["result"]) for pid in chain
                            if probes_by_id.get(pid, {}).get("result")]
        findings.append(Finding(
            finding_id=hashlib.sha256(f"{audit_id}:{item['probe_id']}".encode()).hexdigest()[:16],
            title=f"{hypothesis['owasp_category']} on {method or '?'} {path or '?'}",
            owasp_category=hypothesis["owasp_category"], classification=classification,
            confidence=interpretation["confidence"], cvss_vector=vector, cvss_score=score,
            severity=severity(score), probe_chain=chain, request_summary=request_summary,
            explanation=f"{interpretation['reasoning_summary']} Observed: {interpretation['observed_behavior']}. "
                        f"Expected: {interpretation['expected_behavior']}.",
            remediation=_remediation(hypothesis["owasp_category"])))

    findings.sort(key=lambda f: f.cvss_score, reverse=True)
    return AuditReport(audit_id=audit_id, target_id=target_id, generated_at=time.time(),
        probes_executed=len(trace["probes"]), findings=findings, observations=observations,
        operational_issues=operational_issues, summary=summary)
