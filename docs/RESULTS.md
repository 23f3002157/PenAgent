# Evaluation results

Run date: 2026-10-27. Target: `monisha117/penagent-target-env` (Juice Shop,
DVWS, SREBench-API — see `images/README.md`). Produced by
`demo/run_evaluation.py` and `demo/pentestgpt.py`, scored by `demo/evaluate.py`
against `demo/benchmark-data/ground_truth_chains.json`. Raw output:
`reports/eval-final-guided.json`, `reports/baseline-final-*.json`,
`reports/pentestgpt-final-*.json` (all gitignored, local only — this document
is the durable, tracked record of what they contain).

**Scope.** This is PenAgent's own evaluation against its own ground truth,
run once (n=1, not the paper's 3-run mean/stdev — real-target wall-clock cost
made that impractical in this pass). It is **not** a comparison against Burp
Suite or OWASP ZAP — that stays explicitly deferred. The container's own
`/app/datasets/evaluate.py` was not used for scoring: it loads the ground
truth but never actually compares anything against it (every finding counts
as a match unconditionally, TPR divides by a hardcoded constant) —
`demo/evaluate.py` is a real implementation of the paper's Section 6.2
metrics.

## Guided mode only — autonomous mode dropped

Earlier passes of this evaluation also ran a fully-autonomous mode (real C1
ingestion, real C2 hypothesis generation, zero ground-truth hints, C3
execution with empty bindings). That mode consistently scored 0% TPR across
all three targets: HGS's heuristic planner never supplies a usable concrete
value for any hypothesis needing a path parameter, request body, or specific
header, and PenAgent's existing, correct policy of never inventing those
outside explicit bindings means such hypotheses are rejected rather than
attempted with a wrong value. That's a real, previously-documented finding
about the discovery stage — but repeating "0% everywhere" on every further
run added no new information while doubling run time and reporting
complexity. Per instruction, autonomous mode has been removed from
`demo/run_evaluation.py`, `demo/explore_run.py`, `demo/export_ui_data.py`,
`demo/live_demo.py`, and the operator console. Everything below is **guided**
mode: hypotheses built directly from the ground truth's own documented
exploit chains, submitted through the real C3→C5→C4→C6 pipeline. This does
not test discovery; it tests whether execution, approval gating,
classification, CVSS scoring and report generation are *correct* once
pointed at a known attack path — and, for Juice Shop specifically, whether
expanding architecture (not gaming scoring) can close real gaps.

## Headline metrics (Section 6.2)

| Target | TPR (Recall) | FPR | Precision | F1 | Avg. chain depth | CVSS accuracy | Time to first finding |
|---|---:|---:|---:|---:|---:|---:|---:|
| DVWS | 80.0% (4/5) | 0% | 100% | 88.9% | 1.0 | 86% | 0.09s |
| SREBench-API | 100% (2/2) | 0% | 100% | 100% | 1.0 | 63% | 0.04s |
| Juice Shop | 77.8% (7/9) | 0% | 100% | 87.5% | 1.0 | 89% | 0.09s |
| **Average across targets** | **85.9%** | **0%** | **100%** | **92.1%** | **1.0** | **79.3%** | **0.07s** |

0% FPR on every target: every `CONFIRMED_VULNERABILITY` PenAgent reported
during this evaluation matched a real ground-truth entry — none were wrong.
See "Why guided TPR isn't 100%" below for the specific, named misses.

## Findings, by target

### DVWS (5 ground-truth vulnerabilities, 4 matched)

| ID | Vulnerability | CVSS | Result |
|---|---|---:|---|
| DVWS-API1 | Account BOLA/IDOR | 7.8 | **CONFIRMED** |
| DVWS-API2 | Broken auth (SQLi bypass) | 8.9 | **CONFIRMED** |
| DVWS-API3 | Mass-assignment privilege escalation | 7.2 | **CONFIRMED** (via Component 5 approval) |
| DVWS-API5 | Broken function-level auth (cache purge) | 7.5 | STRONG_SIGNAL (via Component 5 approval) |
| DVWS-API8 | Debug/env secret leak | 6.8 | **CONFIRMED** |

### SREBench-API (2 fully-detailed ground-truth scenarios, both matched)

The live `/scenarios/list` endpoint advertises 20 scenarios, but only 2-3
distinct `endpoint_chain` patterns repeat across them with incrementing
placeholder numbers — not independently actionable. The curated
`ground_truth_chains.json` gives exactly 2 scenarios with real, concrete
exploit values (the ones scored here); this is reported as a limitation of
the provided benchmark, not glossed over.

| ID | Vulnerability | CVSS | Chain depth | Result |
|---|---|---:|---:|---|
| SRE-01 | Cross-service trust-boundary BOLA chain (vault RSA key via tenant-ID leak) | 8.6 | 3 | **CONFIRMED** |
| SRE-02 | Cross-service delegated superadmin vault extraction | 9.4 | 3 | **CONFIRMED** |

### Juice Shop (9 ground-truth vulnerabilities, 7 matched)

Expanded this pass from 3 to 9 live-verified vulnerabilities (JS-04 through
JS-09 are new), each exercised through a real session-chained attack
(register → login → reuse token) built in `demo/run_evaluation.py`'s
`GUIDED_CHAINS`, not isolated single-shot probes.

| ID | Vulnerability | OWASP | CVSS | Result |
|---|---|---|---:|---|
| JS-01 | Admin registration & login bypass (mass assignment) | API2 | 8.1 | **CONFIRMED** — independently cross-checked against Juice Shop's own `/api/Challenges` tracker (`registerAdminChallenge.solved` flipped `false → true`) |
| JS-02 | User BOLA/IDOR data leak (`GET /api/Users/{id}`) | API1 | 7.5 | **CONFIRMED** |
| JS-03 | Admin configuration leakage | API8 | 6.5 | STRONG_SIGNAL |
| JS-04 | Database schema disclosure via SQL injection (`/rest/products/search`) | API8 | 7.5 | **CONFIRMED** |
| JS-05 | Confidential document disclosure (`/ftp/acquisitions.md`) | API8 | 5.3 | **CONFIRMED** |
| JS-06 | Forgotten developer backup via null-byte filter bypass (`/ftp/package.json.bak`) | API8 | 5.3 | not confirmable (see below) |
| JS-07 | Exposed observability metrics (`/metrics`) | API8 | 5.3 | **CONFIRMED** |
| JS-08 | View another user's basket (BOLA) | API1 | 4.3 | **CONFIRMED** |
| JS-09 | Payback Time: negative-price order via unchecked quantity | API6 | 6.5 | **CONFIRMED** |

## Why guided TPR isn't 100% everywhere

- **DVWS (80%, missing DVWS-API5)**: the cache-purge vulnerability was
  deliberately left without a `forbidden_values`/`forbidden_substrings`
  assertion — no single "wrong" response value exists for a purge beyond "it
  happened" — so it classifies `STRONG_SIGNAL` by design, not `CONFIRMED`.
  The action itself (and Component 5's gate on it) is fully exercised and
  correct.
- **Juice Shop, JS-03 (admin-config leak)**: same reasoning as DVWS-API5 —
  the leaked config is a snapshot of live server state, not a fixed secret
  with one canonical "forbidden" value to assert against. STRONG_SIGNAL is
  the right classification, not a miss to "fix."
- **Juice Shop, JS-06 (package.json.bak via null-byte bypass)**: this one
  *is* a real architectural gap, found and left honest rather than hacked
  around. The double-decode null-byte bypass itself works — verified live,
  the server returns HTTP 200 with the backup file's real content — but
  Juice Shop serves it with `Content-Type: application/octet-stream`, and
  `c3-executor/executor/parser.py`'s `parse_response()` only preserves text
  for `text/*` content types; everything else becomes opaque binary
  (`kind="binary"`, `data=None`) before it ever reaches C4. That's a
  defensible binary-safety default (C4 never has to guess at encoding for
  arbitrary binary payloads), so it was not weakened just to turn one more
  finding green. Fixing it for real means teaching the executor to
  text-decode specific binary-labeled responses when a policy explicitly
  expects text — a scoped follow-up, not something to paper over here.

## New since the last pass: text-body disclosure detection

Five of the seven newly-matched Juice Shop findings (JS-04, 05, 07, 08, 09)
needed a genuine capability PenAgent didn't have before: classifying a
disclosure where the forbidden content is a literal substring inside a
non-JSON **text** response body (a markdown file, a Prometheus metrics dump,
a SQL error trace), not a JSON field path. Added `Expectation
.forbidden_substrings` (`penagent_common/config.py`) and extended
`c4-interpreter/interpreter/evidence.py`'s `interpret()` to check for all of
them present in a `text/*` body, folded into the same
CONFIRMED/STRONG_SIGNAL/NEGATIVE decision tree as the existing JSON-path
mechanism — and `c6-report/report/synth.py`'s CVSS impact scoring now treats
a text-substring match as confidentiality impact too, so these findings get
a real, non-zero CVSS score instead of 0.0. Covered by new tests in
`tests/test_interpreter.py`. This is a backward-compatible architecture
improvement, not a target-specific hack — it applies to any future target
whose leaks show up in a non-JSON body.

A real evaluator bug was also found and fixed while expanding this ground
truth: `demo/evaluate.py`'s directory-prefix fallback for templated-ID
matching was letting two *different* static files in the same directory
(JS-05's `acquisitions.md` and JS-06's `package.json.bak`, both under
`/ftp/`) cross-match against the same physical finding, which would have
silently inflated TPR by double-crediting one real finding as two. Fixed
with a targeted guard (skip the prefix fallback when the last path segment
contains a `.`, i.e. it's clearly a specific filename, not a templated ID)
and locked in with a dedicated regression test.

## Independent oracle: Juice Shop's own challenge tracker

Unlike DVWS/SREBench (synthetic mocks, graded only against the curated
ground truth), Juice Shop is a real application with its own built-in
challenge-completion tracking (`GET /api/Challenges`, 112 challenges, live
`solved` flags). The JS-01 finding above was cross-checked against it
directly: `registerAdminChallenge` was `solved: false` before this run's
registration probe and `solved: true` immediately after — confirmed by a
system independent of PenAgent's own classification, not just PenAgent
grading itself.

## Baseline comparison (Section 6.3)

The paper's own baseline design: "Provide PentestGPT with the same OpenAPI
spec and measure which vulnerabilities it identifies through pure language
reasoning, without execution. This isolates the value of our execution +
feedback loop." Two implementations, both scored with the exact same
`demo/evaluate.py` and the expanded 16-entry ground truth above — a genuinely
apples-to-apples comparison against PenAgent's own guided runs:

- **Single-shot** (`demo/baseline_pentestgpt.py`): one prompt, one model
  call, the full endpoint list at once.
- **Multi-stage PentestGPT reproduction** (`demo/pentestgpt.py`, new this
  pass): reproduces the real paper's three-module shape — a Reasoning stage
  that builds a Pentesting Task Tree (3-6 sub-tasks, each scoped to one
  OWASP category), then a focused Generation call per sub-task that sees
  only that sub-task's own endpoints. Still no execution (same no-tool
  baseline methodology as the single-shot version) — this tests whether
  *structuring the reasoning* alone, without ever sending a request, closes
  any of the gap to PenAgent's guided numbers.

**Model substitution, stated plainly**: the paper's baseline uses GPT-4. Per
instruction, this uses all six Ollama models available locally (`ollama
list`) instead — `gemma3:1b-it-qat` (1.0B), `gemma2:2b` (2.6B), `llama3.2:3b`
(3.2B), `phi3:latest` (3.8B), `qwen:latest` (4.0B), `gemma3:4b` (4.3B), real
parameter counts from `ollama show` — not a drop-in replacement for GPT-4 by
any stretch. The comparison below is baseline-vs-PenAgent at this model
scale, not a claim about what a GPT-4-backed PentestGPT would score.

Averaged across all 3 targets (full per-target breakdown in
`ui/data/results.json` and `ui/data/comparison.json`, rendered in the
operator console's Baselines view):

| Approach | Params | Precision | Recall (TPR) | F1 | CVSS acc. | Avg. time |
|---|---:|---:|---:|---:|---:|---:|
| **PenAgent (guided)** | — | **100%** | 85.9% | **92.1%** | 79.3% | live HTTP, no LLM call |
| Llama 3.2 (single-shot) | 3.2B | 89% | 61% | 66% | 25% | 4.3s |
| Phi-3 (single-shot) | 3.8B | 69% | 65% | 64% | 23% | 8.2s |
| Gemma 2 (multi-stage) | 2.6B | 71% | 61% | 62% | 20% | 10.9s |
| Gemma 3 4B (multi-stage) | 4.3B | 56% | 75% | 59% | 22% | 27.8s |
| Gemma 3 4B (single-shot) | 4.3B | 60% | 68% | 59% | 22% | 10.0s |
| Gemma 3 1B (single-shot) | 1.0B | 52% | 67% | 56% | 24% | 4.5s |
| Gemma 2 (single-shot) | 2.6B | 67% | 54% | 54% | 19% | 4.1s |
| Llama 3.2 (multi-stage) | 3.2B | 53% | 64% | 53% | 21% | 17.8s |
| Phi-3 (multi-stage) | 3.8B | 44% | 64% | 48% | 21% | 23.2s |
| Gemma 3 1B (multi-stage) | 1.0B | 44% | 61% | 49% | 23% | 10.0s |
| Qwen2 (either) | 4.0B | 0% | 0% | 0% | — | 2.4–18.3s |

PenAgent (guided) has the highest F1 of every row shown by a wide margin, and
the only perfect precision. **Structuring the reasoning into a Pentesting
Task Tree does not uniformly beat a single prompt** — reported honestly, not
spun to favor either baseline: Gemma 2 and Gemma 3 4B both score *higher* F1
with the multi-stage task-tree shape, but Llama 3.2, Phi-3, and Gemma 3 1B
all score *lower* — the extra structure gives the smaller/weaker models more
chances to hallucinate a plausible-sounding but wrong endpoint per sub-task
rather than committing to one answer. Qwen2 scored 0% under both designs; its
multi-stage run also hit a real, observed robustness failure — Ollama
aborted several of its generation calls with "token repeat limit reached"
(degenerate repetitive output), handled by `demo/pentestgpt.py` as a caught,
logged `generation_error` per sub-task rather than a crash, which is itself
an honest finding about that model's instability under a multi-turn prompt
shape.

### The comparison that actually matters: TPR alone is misleading here

Read naively, some baseline rows show TPR in the same range as PenAgent's
guided mode. That comparison is misleading on its own, and the reason is the
entire point of the paper's Section 6.3 baseline design:

- **The baseline's "CONFIRMED_VULNERABILITY" is an unverified guess.** It
  never sends a single HTTP request, under either design. It cannot tell a
  correct guess from a plausible-sounding wrong one — which is exactly why
  FPR across the eleven baseline rows ranges from roughly a quarter to all of
  everything a given model "confirms" (Qwen2 confirmed nothing real at all,
  under both designs). An operator can't trust a tool's own confirmations
  without independently re-verifying every one — which defeats the purpose.
- **PenAgent's guided CONFIRMED findings have 0% FPR on every target** (see
  the headline metrics table above) because confirmation requires a real
  HTTP response matching an operator-defined, evidence-backed predicate.
  When PenAgent says CONFIRMED, it has proof — a reproducible request/
  response pair, not a guess.
- So the honest reading is: **the baseline is a reasonable endpoint-naming
  heuristic (plausible candidate selection) but has no mechanism to
  distinguish truth from plausible fiction, and restructuring that same
  reasoning into a task tree doesn't fix that — PenAgent's execution loop is
  the missing mechanism.** This is the paper's own stated hypothesis for why
  this baseline exists, and these results support it directly.

## What this does *not* claim

- No comparison against Burp Suite Pro or OWASP ZAP (deferred). The
  PentestGPT baseline is implemented in two forms (above), but with
  open-weight Ollama models, not GPT-4 — not an equivalent substitution.
- Not a full SREBench-API 20-scenario sweep (only 2 of the 20 advertised
  entries have concrete, independently actionable ground truth — see above).
- Not full DVWS/Juice Shop OWASP API Top-10 coverage (5 of DVWS's 10, 9 of
  Juice Shop's 84 curated headline vulns).
- n=1 per target — no variance/stdev across repeated runs, for PenAgent's
  own runs or either baseline.
- Guided mode's bindings are evaluator-authored from the ground truth, not
  agent-discovered; its numbers measure pipeline correctness, not discovery.
  (Fully-autonomous zero-hint discovery was evaluated in an earlier pass and
  consistently scored 0% TPR for reasons documented above — removed from
  ongoing reporting per instruction, not because the finding stopped being
  true.)
- The baselines' FPR is measured against the same ground-truth set as
  PenAgent (5/2/9 entries per target); a baseline suggestion outside that set
  is counted as a false positive even if it happens to be a real,
  uncatalogued issue — the same convention applied to PenAgent's own runs,
  for consistency.
- JS-06 (package.json.bak) is a confirmed, real, exploitable issue — the
  null-byte bypass works, verified live — but is reported as unmatched here
  because PenAgent's own classification pipeline can't yet confirm it
  through the binary-body gap described above; it is not silently excluded
  from the ground truth to inflate the score.
