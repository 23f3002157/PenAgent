"""Deterministic CVSS v3.1 base-score calculator (public FIRST.org formula).

No LLM, no network call, no dependency on raw response text. Inputs are derived
only from already-authorized operator policy (OperationPolicy.risk, Expectation
.protected_fields) and already-validated probe metadata (mutation depth, session
reference) -- see report/synth.py. Severity scoring stays deterministic for the
same reason classification does in c4-interpreter/interpreter/evidence.py.
"""
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (math.floor(int_value / 10000) + 1) / 10


def base_score(av: str, ac: str, pr: str, ui: str, scope: str, c: str, i: str, a: str) -> tuple[str, float]:
    """Returns (vector_string, score) for the given CVSS v3.1 base metrics."""
    iss = 1 - ((1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    pr_table = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
    exploitability = 8.22 * _AV[av] * _AC[ac] * pr_table[pr] * _UI[ui]
    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
    return vector, score


def severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
