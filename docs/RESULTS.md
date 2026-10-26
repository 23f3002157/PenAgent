# Evaluation results

Run date: 2026-10-26. Target: `monisha117/penagent-target-env` (Juice Shop,
DVWS, SREBench-API — see `images/README.md`). Produced by
`demo/run_evaluation.py`, scored by `demo/evaluate.py` against
`demo/benchmark-data/ground_truth_chains.json`. Raw output: `reports/eval-autonomous.json`,
`reports/eval-guided.json`, `reports/eval-metrics.json` (all gitignored, local
only — this document is the durable, tracked record of what they contain).

**Scope.** This is PenAgent's own evaluation against its own ground truth,
run once (n=1, not the paper's 3-run mean/stdev — real-target wall-clock cost
made that impractical in this pass). It is **not** a comparison against Burp
Suite, OWASP ZAP or PentestGPT — that stays explicitly deferred. The
container's own `/app/datasets/evaluate.py` was not used for scoring: it
loads the ground truth but never actually compares anything against it
(every finding counts as a match unconditionally, TPR divides by a hardcoded
constant) — `demo/evaluate.py` is a real implementation of the paper's
Section 6.2 metrics.

## Two modes, never conflated

- **Autonomous** — real C1 spec ingestion, real C2 hypothesis generation, C3
  execution through `/run` with empty bindings, exactly as
  `demo/docker_verify.py` already does for the synthetic fixture. No
  ground-truth-specific hint is ever supplied. This measures current,
  unaided discovery capability on real (non-synthetic) targets.
- **Guided** — hypotheses built directly from the ground truth's own
  documented exploit chains, submitted straight through C3→C5→C4→C6. This
  does **not** test discovery; it tests whether execution, approval gating,
  classification and report generation are *correct* once pointed at a known
  attack path.

## Headline metrics (Section 6.2)

| Target | Mode | TPR | FPR | Avg. chain depth | CVSS accuracy | Time to first finding | Unnecessary-action rate | Replanning freq. |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DVWS | Autonomous | 0% | — | 1.0 | — | 0.80s | 33% | 0% |
| DVWS | Guided | **80%** (4/5) | 0% | 1.0 | 86% | 0.05s | 40% | 0% |
| SREBench-API | Autonomous | 0% | — | — | — | — | — | 0% |
| SREBench-API | Guided | **100%** (2/2) | 0% | 1.0 | 63% | 0.03s | 0% | 0% |
| Juice Shop | Autonomous | 0% | — | 1.0 | — | 0.46s | 50% | 0% |
| Juice Shop | Guided | **33%** (1/3) | 0% | 1.0 | 99% | 0.59s | 0% | 0% |

FPR and CVSS accuracy are "—" where zero probes reached `executed`/no
findings were produced at all (no denominator). TPR counts only
`CONFIRMED_VULNERABILITY` matches against ground truth; see "Why guided TPR
isn't 100%" below for the partial scores.

## Findings, by target and mode

### DVWS (5 ground-truth vulnerabilities)

| ID | Vulnerability | Guided result | Autonomous result |
|---|---|---|---|
| DVWS-API1 | Account BOLA/IDOR | **CONFIRMED**, CVSS 7.5 | not reached |
| DVWS-API2 | Broken auth (SQLi bypass) | **CONFIRMED**, CVSS 5.3 | not reached |
| DVWS-API3 | Mass-assignment privilege escalation | **CONFIRMED**, CVSS 8.2 (via Component 5 approval) | not reached |
| DVWS-API5 | Broken function-level auth (cache purge) | STRONG_SIGNAL, CVSS 7.5 (via Component 5 approval) | STRONG_SIGNAL equivalent action approved+executed, not independently confirmed |
| DVWS-API8 | Debug/env secret leak | **CONFIRMED**, CVSS 7.5 | STRONG_SIGNAL, CVSS 7.5 (no forbidden-value foreknowledge) |

### SREBench-API (2 fully-detailed ground-truth scenarios)

The live `/scenarios/list` endpoint advertises 20 scenarios, but only 2-3
distinct `endpoint_chain` patterns repeat across them with incrementing
placeholder numbers — not independently actionable. The curated
`ground_truth_chains.json` gives exactly 2 scenarios with real, concrete
exploit values (the ones scored here); this is reported as a limitation of
the provided benchmark, not glossed over.

| ID | Vulnerability | Guided result | Autonomous result |
|---|---|---|---|
| SRE-01 | Cross-service BOLA (profile leak) | **CONFIRMED**, CVSS 5.3 | not reached |
| SRE-02 | Cross-service trust-boundary header bypass (vault RSA key) | **CONFIRMED**, CVSS 5.3 | not reached |

### Juice Shop (3 curated headline vulns of 84 total)

| ID | Vulnerability | Guided result | Autonomous result |
|---|---|---|---|
| JS-01 | Admin registration (mass assignment) | **CONFIRMED**, CVSS 8.2, approved via Component 5 — **independently confirmed by Juice Shop's own `/api/Challenges` tracker**, `registerAdminChallenge.solved` flipped `false → true` | not in the provided sample spec (see below) |
| JS-02 | Users BOLA/IDOR | not exercised this pass (needs a login/session step; time-boxed out) | not reached |
| JS-03 | Admin configuration leak | STRONG_SIGNAL, CVSS 5.3 | STRONG_SIGNAL, CVSS 5.3 |

## Why autonomous TPR is 0% everywhere — and why that's an honest, specific finding, not a bug

Three distinct, real limitations were found while building this evaluation,
each confirmed by direct, reproducible testing against the live targets
(not inferred):

1. **C4's mutation-discovery only recognizes synthetic-fixture-shaped
   hints.** `interpreter/evidence.py` keys mutation strategy off literal JSON
   field names (`missing_header`, `invalid_parameter`, `missing_parameter`,
   `compare_auth_context`) that the project's own synthetic fixture happens
   to use. Real targets don't: SREBench returns
   `{"detail": "Missing trusted internal headers."}`, not a `missing_header`
   key. A header/parameter-bypass vulnerability a real API hints at in free
   text is invisible to the current mutation engine.
2. **HGS's heuristic planner never supplies a usable concrete value.** Its
   fallback hint is a literal placeholder string (`{"test_id":
   "alternate_tenant_id"}`), which isn't even a `Binding` field name, so any
   single-step hypothesis with a payload hint is rejected immediately
   (`unresolved_hypothesis_payload_hint_supply_step_binding`) rather than
   attempted with a wrong value. Combined with PenAgent's existing, correct
   policy of never inventing path/body parameters outside explicit bindings
   (`docs/EXECUTION.md` already documents this for `alternate_tenant_id`),
   **any ground-truth vulnerability requiring a path parameter, a request
   body, or a specific header value is currently unreachable by
   fully-autonomous `/run` execution with no human-supplied binding.** Only
   parameter-free GET endpoints (DVWS's `/debug/env`, Juice Shop's
   `/rest/admin/application-configuration`) were autonomously reachable —
   and both were found, correctly classified `STRONG_SIGNAL` (not
   `CONFIRMED`, since confirming a specific leaked value requires
   foreknowledge an autonomous run doesn't have).
3. **`Expectation.owasp_categories` requires an exact string match against
   whatever category HGS's own planner assigns**, and HGS's taxonomy
   (`"API1:BOLA"`, `"API8:Security_Misconfiguration"`) differs from the
   paper/ground-truth's (`"API1:2023 - Broken Object Level Authorization"`).
   An operator restricting `owasp_categories` for an autonomous audit would
   silently suppress every confirmation. `demo/eval_targets.py` leaves this
   field empty for autonomous-mode configs for exactly this reason — worth
   fixing in the policy/HGS integration itself as follow-up work, not papered
   over here.

None of this is a regression from the Component 3/4/5/6 verification already
recorded in `docs/VERIFICATION.md` — the guided-mode numbers above prove
execution, approval gating, classification and reporting all work correctly
once pointed at a real attack path. What this evaluation adds is an honest
measurement of *discovery*, specifically: it doesn't yet generalize past the
synthetic fixture's response conventions. That's a concrete, scoped
follow-up item, not a vague caveat.

## Why guided TPR isn't 100% everywhere

- **DVWS (80%)**: the 5th vulnerability (cache purge, DVWS-API5) was
  deliberately left without a `forbidden_values` assertion (no single
  "wrong" response value exists for a purge beyond "it happened"), so it
  classifies `STRONG_SIGNAL` by design, not `CONFIRMED`. The action itself
  (and Component 5's gate on it) is fully exercised and correct.
- **Juice Shop (33%)**: JS-02 (Users BOLA) needs a prior login/session step
  this pass didn't build out (time-boxed); JS-03 (admin-config) is a STRONG
  signal, same reasoning as DVWS-API5 above — the leaked config has no single
  canonical "forbidden" value to assert against (it's a snapshot of live
  server configuration, not a fixed secret).

## Independent oracle: Juice Shop's own challenge tracker

Unlike DVWS/SREBench (synthetic mocks, graded only against the curated
ground truth), Juice Shop is a real application with its own built-in
challenge-completion tracking (`GET /api/Challenges`, 112 challenges,
live `solved` flags). The JS-01 finding above was cross-checked against it
directly: `registerAdminChallenge` was `solved: false` before this run's
registration probe and `solved: true` immediately after — confirmed by a
system independent of PenAgent's own classification, not just PenAgent
grading itself.

## Baseline: PentestGPT-style prompt-only reasoning (Section 6.3)

The paper's own baseline design: "Provide PentestGPT with the same OpenAPI
spec and measure which vulnerabilities it identifies through pure language
reasoning, without execution. This isolates the value of our execution +
feedback loop." Implemented in `demo/baseline_pentestgpt.py`, scored with the
exact same `demo/evaluate.py` and ground truth as PenAgent's own runs above
-- a genuinely apples-to-apples comparison.

**Model substitution, stated plainly**: the paper's baseline uses GPT-4. Per
instruction, this uses six locally-hosted open-weight models via Ollama
instead -- `gemma3:1b-it-qat` (1.0B), `gemma2:2b` (2.6B), `llama3.2:3b`
(3.2B), `phi3:latest` (3.8B), `qwen:latest` (4.0B), `gemma3:4b` (4.3B),
real parameter counts from `ollama show` -- not a drop-in replacement for
GPT-4 by any stretch. The comparison below is baseline-vs-PenAgent at this
model scale, not a claim about what a GPT-4-backed PentestGPT would score.

Averaged across all 3 targets (full per-target breakdown in
`ui/data/results.json`, rendered in the operator console's Baselines view):

| Approach | Params | Precision | Recall (TPR) | F1 | CVSS acc. | Avg. time |
|---|---:|---:|---:|---:|---:|---:|
| **PenAgent (guided)** | — | **100%** | 71% | **80%** | 83% | live HTTP, no LLM call |
| Llama 3.2 | 3.2B | 67% | 69% | 66% | 22% | 4.3s |
| Phi-3 | 3.8B | 56% | 80% | 65% | 20% | 8.2s |
| Gemma 3 | 4.3B | 47% | 76% | 57% | 18% | 9.9s |
| Gemma 3 | 1.0B | 46% | 71% | 55% | 19% | 8.3s |
| Gemma 2 | 2.6B | 56% | 58% | 54% | 16% | 8.0s |
| Qwen2 | 4.0B | 0% | 0% | 0% | — | 2.6s |
| PenAgent (autonomous) | — | 0% | 0% | 0% | — | live HTTP, no LLM call |

PenAgent (guided) has the highest F1 of all eight rows and the only perfect
precision. Qwen2 -- the *largest* baseline model at 4.0B parameters --
produced the *lowest* precision of the six (every one of its "confirmed"
findings was a miss), well below the smallest model (Gemma 3, 1.0B, 46%
precision): raw parameter count does not predict reliability here.

### The comparison that actually matters: TPR alone is misleading here

Read naively, the baseline's TPR looks *competitive with or better than*
PenAgent's guided mode in places (e.g. phi3 hit 100% TPR on Juice Shop vs.
PenAgent's guided 33%). That comparison is misleading on its own, and the
reason is the entire point of the paper's Section 6.3 baseline design:

- **The baseline's "CONFIRMED_VULNERABILITY" is an unverified guess.** It
  never sends a single HTTP request. It cannot tell a correct guess from a
  plausible-sounding wrong one -- which is exactly why its **average FPR
  per model ranges 33-100% across the six** (Qwen2 confirmed nothing real
  at all): a third to all of everything a given model "confirms" is not a
  real ground-truth vulnerability, asserted with the same flat confidence
  as the correct ones. A FPR that high in a real audit means an operator
  can't trust the tool's own confirmations at all without independently
  re-verifying every one -- which defeats the purpose.
- **PenAgent's guided/autonomous CONFIRMED findings have 0% FPR everywhere**
  (see the headline metrics table above) because confirmation requires a
  real HTTP response matching an operator-defined, evidence-backed
  predicate. When PenAgent says CONFIRMED, it has proof -- a reproducible
  request/response pair, not a guess.
- So the honest reading is: **the baseline is a reasonable endpoint-naming
  heuristic (plausible candidate selection) but has no mechanism to
  distinguish truth from plausible fiction; PenAgent's execution loop is
  exactly that missing mechanism.** This is the paper's own stated
  hypothesis for why this baseline exists, and these results support it
  directly.

## What this does *not* claim

- No comparison against Burp Suite Pro or OWASP ZAP (deferred). The
  PentestGPT-style baseline is implemented (above), but with open-weight
  Ollama models, not GPT-4 -- not an equivalent substitution.
- Not a full SREBench-API 20-scenario sweep (only 2 of the 20 advertised
  entries have concrete, independently actionable ground truth — see above).
- Not full DVWS/Juice Shop OWASP API Top-10 coverage (5 of DVWS's 10, 3 of
  Juice Shop's 84 curated headline vulns).
- n=1 per (target, mode) — no variance/stdev across repeated runs, for
  PenAgent's own runs or the baseline.
- Guided mode's bindings are evaluator-authored from the ground truth, not
  agent-discovered; its numbers measure pipeline correctness, not discovery.
- The baseline's FPR is measured against the same narrow ground-truth set as
  PenAgent (5/10/2 entries per target); a baseline suggestion outside that
  set is counted as a false positive even if it happens to be a real,
  uncatalogued issue -- the same convention applied to PenAgent's own runs,
  for consistency.
