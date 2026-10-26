"""Real Section-6.2 metrics evaluator.

Replaces the container's /app/datasets/evaluate.py, which loads the ground
truth and never actually compares anything against it (every finding counts
as a match unconditionally; TPR divides by a hardcoded constant). This module
does the real comparison, is pure (no network/filesystem beyond what callers
pass in), and is unit-tested in tests/test_evaluate.py.

A "RunResult" is what demo/run_evaluation.py assembles after driving an
audit to completion:
    {"report": <AuditReport dict from GET /v1/audits/{audit}/report>,
     "probe_statuses": [<ExecutionResult.status for every probe attempted>],
     "replanning_transitions": <int>, "hypotheses_processed": <int>,
     "time_to_first_finding_seconds": <float | None>}
"""
from __future__ import annotations


def _endpoint_tokens(ground_truth_entry: dict) -> set[str]:
    """Path-looking substrings mentioned anywhere in a ground-truth entry."""
    tokens = set()
    for text in [ground_truth_entry.get("target_endpoint", "")] + ground_truth_entry.get("exploit_chain", []):
        for word in text.split():
            word = word.strip(",;")
            if word.startswith("/"):
                tokens.add(word.split("?")[0])
    return tokens


# Keyword -> canonical OWASP API Security Top 10 2023 number. Different
# sources label the same category differently: PenAgent's own guided-mode
# config writes the full "API1:2023 - Broken Object Level Authorization";
# HGS's own planner (autonomous mode) uses its own abbreviated taxonomy
# ("API1:BOLA"); a prompt-only LLM baseline may drop the numeric prefix
# entirely and just say "Broken Object Level Authorization" (observed live --
# see demo/baseline_pentestgpt.py). Matching only an "APIn" string prefix is
# brittle against that last, common case, so categories are canonicalized by
# keyword instead.
_CATEGORY_KEYWORDS = [
    ("API1", ("object level authorization", "bola", "idor")),
    ("API2", ("broken authentication", "broken_auth")),
    ("API3", ("object property level authorization", "bopla", "mass assignment")),
    ("API4", ("unrestricted resource consumption", "resource consumption", "rate limit")),
    ("API5", ("function level authorization", "bfla")),
    ("API6", ("sensitive business flow", "business flow")),
    ("API7", ("server side request forgery", "ssrf")),
    ("API8", ("security misconfiguration", "misconfig")),
    ("API9", ("improper inventory", "inventory management")),
    ("API10", ("unsafe consumption", "third-party")),
]


def _owasp_prefix(category: str) -> str:
    text = (category or "").lower()
    for number, keywords in _CATEGORY_KEYWORDS:
        if any(k in text for k in keywords):
            return number
    # Fall back to a literal "APIn" prefix if present (covers any category
    # string that doesn't match a known keyword, e.g. a future/unlisted one).
    return (category or "").split(":")[0].split(" ")[0].upper()


def _matches(finding: dict, ground_truth_entry: dict) -> bool:
    # SREBench's curated scenarios carry no owasp_category field at all (only
    # DVWS/Juice Shop's entries do); only compare the category when the
    # ground truth actually states one, rather than treating "missing" as
    # API0/none.
    gt_category = ground_truth_entry.get("owasp_category")
    if gt_category and _owasp_prefix(finding.get("owasp_category", "")) != _owasp_prefix(gt_category):
        return False
    title = finding.get("title", "")
    tokens = _endpoint_tokens(ground_truth_entry)
    if not tokens:
        return False
    # A ground-truth token may be a templated path ("/accounts/{id}", matching
    # a finding's title directly) or a resolved one with a literal ID
    # ("/accounts/2", as SREBench's curated exploit_chain always is -- it has
    # no separate target_endpoint field). For the latter, the finding's title
    # keeps the node's own {param} placeholder, so compare the static
    # directory prefix (up to the final "/") instead of the exact string.
    for token in tokens:
        if token in title:
            return True
        prefix = token.rsplit("/", 1)[0] + "/"
        if len(prefix) > 1 and prefix in title:
            return True
    return False


def match_findings(findings: list[dict], ground_truth: list[dict]) -> dict[str, list[dict]]:
    """Returns {ground_truth_id: [matching findings]} for every ground-truth entry."""
    matches: dict[str, list[dict]] = {}
    for entry in ground_truth:
        gid = entry.get("vuln_id") or entry.get("scenario_id")
        matches[gid] = [f for f in findings if _matches(f, entry)]
    return matches


def compute_metrics(run: dict, ground_truth: list[dict]) -> dict:
    report = run["report"]
    findings = report.get("findings", [])
    confirmed = [f for f in findings if f["classification"] == "CONFIRMED_VULNERABILITY"]
    matches = match_findings(confirmed, ground_truth)

    true_positives = sum(1 for m in matches.values() if m)
    total_ground_truth = len(ground_truth) or 1
    tpr = true_positives / total_ground_truth

    matched_finding_ids = {f["finding_id"] for group in matches.values() for f in group}
    unmatched_confirmed = [f for f in confirmed if f["finding_id"] not in matched_finding_ids]
    fpr = (len(unmatched_confirmed) / len(confirmed)) if confirmed else 0.0

    chain_depths = [len(f.get("probe_chain", [])) or 1 for f in findings]
    avg_chain_depth = sum(chain_depths) / len(chain_depths) if chain_depths else 0.0

    cvss_diffs = []
    for gid, group in matches.items():
        if not group:
            continue
        ground_truth_score = next(e["cvss_score"] for e in ground_truth if (e.get("vuln_id") or e.get("scenario_id")) == gid)
        cvss_diffs.append(min(abs(f["cvss_score"] - ground_truth_score) for f in group))
    cvss_accuracy = (1 - sum(cvss_diffs) / len(cvss_diffs) / 10) if cvss_diffs else None

    statuses = run.get("probe_statuses", [])
    unnecessary = sum(1 for s in statuses if s in {"blocked", "duplicate", "budget_exhausted"})
    unnecessary_action_rate = (unnecessary / len(statuses)) if statuses else 0.0

    hypotheses = run.get("hypotheses_processed", 0) or 1
    replanning_frequency = run.get("replanning_transitions", 0) / hypotheses

    # precision/recall/F1 in their standard information-retrieval sense --
    # recall is exactly true_positive_rate (every ground-truth entry is
    # equally weighted as "1 relevant item"), precision is the fraction of
    # CONFIRMED findings that were real, i.e. exactly (1 - false_positive_rate).
    # Both are derivable from the fields above; reported directly because
    # "precision/recall/F1" is the vocabulary a paper comparison expects.
    precision = (true_positives / len(confirmed)) if confirmed else (1.0 if not ground_truth else 0.0)
    recall = tpr
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "true_positive_rate": round(tpr, 3),
        "false_positive_rate": round(fpr, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1_score, 3),
        "avg_exploit_chain_depth": round(avg_chain_depth, 2),
        "cvss_score_accuracy": round(cvss_accuracy, 3) if cvss_accuracy is not None else None,
        "time_to_first_finding_seconds": run.get("time_to_first_finding_seconds"),
        "unnecessary_action_rate": round(unnecessary_action_rate, 3),
        "replanning_frequency": round(replanning_frequency, 3),
        "total_ground_truth": len(ground_truth),
        "true_positives": true_positives,
        "confirmed_findings": len(confirmed),
        "total_probes": len(statuses),
        "matched_ground_truth_ids": sorted([gid for gid, group in matches.items() if group]),
        "unmatched_ground_truth_ids": sorted([gid for gid, group in matches.items() if not group]),
    }


def juice_shop_challenge_delta(before: list[dict], after: list[dict]) -> dict:
    """Independent oracle: which Juice Shop challenges flipped solved by the audit."""
    before_solved = {c["id"] for c in before if c.get("solved")}
    after_solved = {c["id"] for c in after if c.get("solved")}
    newly_solved = after_solved - before_solved
    by_id = {c["id"]: c for c in after}
    return {
        "newly_solved_count": len(newly_solved),
        "newly_solved": [{"id": i, "name": by_id[i]["name"], "category": by_id[i]["category"]} for i in sorted(newly_solved)],
        "total_challenges": len(after),
        "total_solved_before": len(before_solved),
        "total_solved_after": len(after_solved),
    }
