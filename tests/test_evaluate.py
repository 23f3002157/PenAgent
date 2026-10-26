"""Unit tests for demo/evaluate.py's metrics math -- deterministic, no live target."""
from demo.evaluate import compute_metrics, juice_shop_challenge_delta, match_findings

GROUND_TRUTH = [
    {"vuln_id": "X-1", "owasp_category": "API1:2023 - Broken Object Level Authorization",
     "target_endpoint": "/api/v1/accounts/{account_id}", "cvss_score": 7.8, "exploit_chain": ["GET /api/v1/accounts/2"]},
    {"vuln_id": "X-2", "owasp_category": "API8:2023 - Security Misconfiguration",
     "target_endpoint": "/api/v1/debug/env", "cvss_score": 6.8, "exploit_chain": ["GET /api/v1/debug/env"]},
]


def finding(finding_id, owasp_category, title, cvss_score, classification="CONFIRMED_VULNERABILITY", probe_chain=None):
    return {"finding_id": finding_id, "owasp_category": owasp_category, "title": title, "cvss_score": cvss_score,
            "classification": classification, "probe_chain": probe_chain or ["p1"]}


def test_match_findings_matches_by_category_and_endpoint():
    findings = [finding("f1", "API1:2023 - Broken Object Level Authorization", "API1:2023 on GET /api/v1/accounts/{account_id}", 7.5)]
    matches = match_findings(findings, GROUND_TRUTH)
    assert matches["X-1"] == findings
    assert matches["X-2"] == []


def test_match_findings_matches_resolved_id_against_templated_title():
    # SREBench-style ground truth: no target_endpoint, only a literal resolved
    # ID inside a free-text exploit_chain entry -- must still match a finding
    # whose title keeps the node's {param} placeholder.
    ground_truth = [{"scenario_id": "SRE-01", "owasp_category": "API1:2023 - Broken Object Level Authorization",
                      "exploit_chain": ["GET /users/v1/profile/usr_102 -> leak tenant ID"]}]
    findings = [finding("f1", "API1:2023 - Broken Object Level Authorization", "API1:2023 on GET /users/v1/profile/{user_id}", 5.3)]
    assert match_findings(findings, ground_truth)["SRE-01"] == findings


def test_match_findings_category_keyword_matches_dropped_numeric_prefix():
    # Observed live from demo/baseline_pentestgpt.py: a small local model given
    # the exact "API1:2023 - Broken Object Level Authorization" taxonomy to
    # copy still drops the numeric prefix and just returns the category name.
    findings = [finding("f1", "Broken Object Level Authorization", "Broken Object Level Authorization on GET /api/v1/accounts/{account_id}", 0.0)]
    assert match_findings(findings, GROUND_TRUTH)["X-1"] == findings


def test_match_findings_requires_same_owasp_prefix():
    findings = [finding("f1", "API3:2023 - Broken Object Property Level Authorization", "... /api/v1/accounts/{account_id}", 7.5)]
    assert match_findings(findings, GROUND_TRUTH)["X-1"] == []


def test_compute_metrics_full_tpr_zero_fpr():
    findings = [
        finding("f1", "API1:2023 - Broken Object Level Authorization", "API1:2023 on GET /api/v1/accounts/{account_id}", 7.9, probe_chain=["p1"]),
        finding("f2", "API8:2023 - Security Misconfiguration", "API8:2023 on GET /api/v1/debug/env", 6.5, probe_chain=["p1", "p2"]),
    ]
    run = {"report": {"findings": findings}, "probe_statuses": ["executed", "executed", "blocked"],
           "replanning_transitions": 1, "hypotheses_processed": 2, "time_to_first_finding_seconds": 4.2}
    metrics = compute_metrics(run, GROUND_TRUTH)
    assert metrics["true_positive_rate"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["true_positives"] == 2 and metrics["confirmed_findings"] == 2
    assert metrics["avg_exploit_chain_depth"] == 1.5
    assert metrics["cvss_score_accuracy"] is not None and 0 < metrics["cvss_score_accuracy"] <= 1
    assert metrics["unnecessary_action_rate"] == round(1 / 3, 3)
    assert metrics["replanning_frequency"] == 0.5
    assert metrics["time_to_first_finding_seconds"] == 4.2
    assert metrics["matched_ground_truth_ids"] == ["X-1", "X-2"]
    assert metrics["unmatched_ground_truth_ids"] == []


def test_compute_metrics_partial_tpr_and_false_positive():
    findings = [
        finding("f1", "API1:2023 - Broken Object Level Authorization", "API1:2023 on GET /api/v1/accounts/{account_id}", 8.0),
        finding("f2", "API5:2023 - Broken Function Level Authorization", "API5:2023 on DELETE /somewhere/unexpected", 5.0),
    ]
    run = {"report": {"findings": findings}, "probe_statuses": ["executed"], "replanning_transitions": 0, "hypotheses_processed": 1,
           "time_to_first_finding_seconds": None}
    metrics = compute_metrics(run, GROUND_TRUTH)
    assert metrics["true_positive_rate"] == 0.5  # 1 of 2 ground-truth entries matched
    assert metrics["false_positive_rate"] == 0.5  # 1 of 2 confirmed findings unmatched
    assert metrics["unmatched_ground_truth_ids"] == ["X-2"]
    assert metrics["time_to_first_finding_seconds"] is None


def test_compute_metrics_handles_no_findings():
    run = {"report": {"findings": []}, "probe_statuses": [], "replanning_transitions": 0, "hypotheses_processed": 0,
           "time_to_first_finding_seconds": None}
    metrics = compute_metrics(run, GROUND_TRUTH)
    assert metrics["true_positive_rate"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["cvss_score_accuracy"] is None
    assert metrics["avg_exploit_chain_depth"] == 0.0


def test_juice_shop_challenge_delta():
    before = [{"id": 1, "solved": False}, {"id": 2, "solved": True}]
    after = [{"id": 1, "solved": True, "name": "Admin Registration", "category": "Broken Auth"},
             {"id": 2, "solved": True, "name": "Already solved", "category": "x"}]
    delta = juice_shop_challenge_delta(before, after)
    assert delta["newly_solved_count"] == 1
    assert delta["newly_solved"] == [{"id": 1, "name": "Admin Registration", "category": "Broken Auth"}]
    assert delta["total_solved_before"] == 1 and delta["total_solved_after"] == 2
