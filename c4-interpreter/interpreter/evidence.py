from penagent_common.models import Category, Interpretation


def lookup(value, path):
    try:
        for part in path.split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
        return value
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def interpret(result, hypothesis, probe, rule, prior=None) -> Interpretation:
    expectation = rule.expectation if rule else None
    expected = expectation.expected_behavior if expectation else "No operator security expectation supplied; success alone proves no flaw."
    data = result.parsed.data if result.parsed else None
    code = result.status_code
    kind = Category.WEAK_SIGNAL
    confidence = .35
    action = "preserve"
    reason = "Observed response lacks enough context to establish an exploit."
    observed = f"HTTP {code}; {result.parsed.kind if result.parsed else 'no parsed body'}; hypothesis {hypothesis.owasp_category}"
    replan = False
    protected = [p for p in expectation.protected_fields if lookup(data, p) not in (None, "", [], {})] if expectation else []
    signals = [p for p in expectation.signal_fields if lookup(data, p) not in (None, "", [], {})] if expectation else []
    if result.status != "executed":
        kind, confidence, action = Category.ERROR_CRASH, .95, "stop"
        reason = "Execution did not complete. Transport or policy error is not evidence of a crash or vulnerability."
    elif code is not None and code >= 500:
        kind, confidence, action = Category.ERROR_CRASH, .95, "stop"
        reason = "Server returned 5xx. Record a potential logic/availability issue and halt; exploit success is unproven."
    elif expectation and code in expectation.denied_statuses and not protected and not signals:
        kind, confidence, action = Category.NEGATIVE, .9, "next_hypothesis"
        reason = "The configured security rejection occurred; no successful access was demonstrated."
    elif code in {401, 403, 404} and not protected and not signals:
        kind, confidence, action = Category.NEGATIVE, .8, "next_hypothesis"
        reason = "The request was rejected or the resource was absent, without evidence of a security violation."
    elif result.parsed and result.parsed.parse_error:
        reason = "Response parsing failed independently of HTTP success; preserve the bounded body hash."
    elif expectation and code is not None and 200 <= code < 500:
        matches = bool(expectation.forbidden_values) and all(lookup(data, p) == v for p, v in expectation.forbidden_values.items())
        auth_context_matches = (not expectation.requires_anonymous or probe.binding.session_ref is None) and (not expectation.owasp_categories or hypothesis.owasp_category in expectation.owasp_categories)
        if matches and protected and auth_context_matches:
            kind, confidence, action = Category.CONFIRMED_VULNERABILITY, .98, "replan"
            replan = True
            reason = "Configured forbidden object/context values and protected fields were observed in the tested authentication context."
        elif (protected or signals) and auth_context_matches:
            kind, confidence, action = Category.STRONG_SIGNAL, .75, "mutate"
            reason = "Response includes fields relevant to the hypothesis and conflicts with expected rejection; the full violation is not yet established."
        else:
            reason = "HTTP success did not satisfy the operator-defined violation predicate."
    prior_refs = []
    for item in prior or []:
        previous = item.get("result")
        if previous and previous["probe_id"] != result.probe_id and previous["op"] == result.op and previous["hypothesis_id"] == hypothesis.id:
            if expectation and previous["status_code"] in expectation.denied_statuses:
                prior_refs.append(previous["probe_id"])
    if prior_refs and kind in {Category.STRONG_SIGNAL, Category.CONFIRMED_VULNERABILITY}:
        reason += " Prior stored probes of this hypothesis demonstrated rejection, supporting a response difference."
    return Interpretation(audit_id=result.audit_id, hypothesis_id=hypothesis.id, probe_id=result.probe_id,
                          classification=kind, confidence=confidence, evidence_refs=[result.probe_id] + ([result.parsed.body_sha256] if result.parsed else []) + prior_refs,
                          observed_behavior=observed, expected_behavior=expected, reasoning_summary=reason,
                          state_changes=result.state_changes, next_action=action, replan_justified=replan,
                          human_approval_required=result.approval_required, error=result.error)
