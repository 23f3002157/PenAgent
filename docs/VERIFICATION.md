# Verification record

Date: 2026-10-24 (Asia/Calcutta). Status: **PARTIALLY COMPLETE** because six
historical regression cases still require missing authoritative inputs. New
implementation, real HTTP integration, Docker and Gemini checks passed.
No benchmarks, benchmark specifications, ground truth or datasets were created.

## Commands executed and results

Commands ran from repository root using the sibling workspace virtualenv:

```powershell
../.venv/Scripts/python.exe -m pip install -e '.[test]'
../.venv/Scripts/python.exe -B -m pytest tests -q --cov=interpreter --cov-branch --cov-report=term-missing --cov-report=json:reports/coverage.json --junitxml=reports/new-tests.xml
../.venv/Scripts/python.exe -B -m demo.run --output reports/demo.json
../.venv/Scripts/python.exe -B -m demo.gemini_check --model gemini-3.1-flash-lite
../.venv/Scripts/python.exe -B -m demo.gemini_application
../.venv/Scripts/python.exe -B -m demo.juice_check --url http://127.0.0.1:3000
../.venv/Scripts/python.exe -B -m demo.prepare_docker
Docker compose build
Docker compose up -d --wait --wait-timeout 120
../.venv/Scripts/python.exe -B -m demo.docker_verify --require-gemini --output reports/docker-gemini.json
Docker compose restart executor interpreter
../.venv/Scripts/python.exe -B -m demo.docker_verify --restart-check --output reports/docker-gemini.json
```

- New unit/contract/integration/recovery suite: **112 passed in 81.51 seconds**.
- Interpreter combined statement/branch coverage: **88%**, service 94%, Gemini
  adapter 92%. Coverage is not exhaustive.
- Original C1 full suite: **6 passed, 5 failed** due missing specifications and
  test-environment inputs. Original C2: **8 passed, 1 failed** due missing ground truth.
- Available regressions rerun: **C1 6 passed / 5 deselected; C2 8 passed / 1
  deselected**. Deselected cases remain BLOCKED, not counted as passing.
- Deterministic four-service TCP demo: PASSED, three real target probes.
- Real Gemini catalogue/authentication and native structured output: PASSED with
  gemini-3.1-flash-lite. Another listed model returned 404; listing is insufficient.
- Real Gemini application over C1-C4 TCP: PASSED, three calls with validated output
  and recorded total token counts 307, 280 and 287.
- All four Docker images built; all five containers healthy on Python 3.11.
- Actual Docker C1-C2-C3-C4-Gemini loop: PASSED, audit docker-e6f480b26b,
  three main probes plus a separate controlled-error audit. Planner feedback/replan
  handoff records are done; missing C4 machine authentication is rejected with 401.
- C3/C4 restart: PASSED, identical session state and stored response hash after
  restart. This verifies SQLite persistence, not a LangGraph checkpointer.
- Existing authorized Juice Shop root: HTTP 200 / WEAK_SIGNAL. Read-only C3/C4
  supplementary check; no vulnerability or full benchmark integration claimed.

Reports, JUnit, coverage, logs, runtime state and .env are ignored local outputs.
No commit or push occurred. Task-owned containers remain running. The existing
Juice Shop container was retained without replacement and its existing binding
on port 3000 was preserved.

## Observed real request flow

1. C1 retrieves the synthetic fixture OpenAPI via HTTP and persists its graph.
2. C2 retrieves that surface and generates its actual ranked hypothesis queue.
3. C3 consumes the queue and sends GET /admin/object. HTTP 200 contains an
   operator-configured signal and missing_header=X-Test-Context: STRONG_SIGNAL.
4. Gemini proposes the approved X-Test-Context: fixture-only header. C4 selects
   that validated candidate; C3 repeats schema/authorization/risk/budget checks.
5. The follow-up HTTP 200 contains owner=tenant-b and synthetic protected data.
   The configured violation predicate is satisfied: CONFIRMED_VULNERABILITY for
   this explicitly simulated case only. The chain stops and C2 receives handoffs.
6. GET /admin/denied returns 403 without violation evidence: NEGATIVE.
7. Separate GET /admin/error returns deliberate 500: ERROR_CRASH and stop.
   Repetition is rejected with attempts=0/service_chain_halted. No exploit proof
   is asserted. Cancellation also blocks subsequent execution.
8. Audit state and evidence survive an actual executor/interpreter restart.

An initial final Docker verification mixed the intentional 500 into the main
queue; the executor correctly halted the audit. The verification script now
defers this hypothesis to its separate error audit and accepts confirmed-stop
outcomes. The successful rerun is distinct from that failed harness run.

## Repairs and acceptance limits

Verification repaired C1/C2 SQLite connection leaks, model recommendations that
were recorded without selecting candidates, confirmed-stop planner handoff loss,
strict-contract error handling, Docker network publication and model/interservice
timeout alignment. C1/C2 public routes, schemas and database schemas are preserved.

The six blocked historical cases require authoritative Juice Shop/DVWS specs
and future SREBench specs/ground truth. Docker is available now; those inputs
remain absent. They were not fabricated or silently counted as passes.

| Acceptance area | Status | Evidence |
|---|---|---|
| C1/C2 available compatibility | VERIFIED | 14 available regression passes and real HTTP graph/queue flow |
| All original regression cases pass | BLOCKED | six missing-input cases |
| C3 strict tools, sessions and authorized HTTP | VERIFIED | 112-test suite; live TCP and Docker |
| C4 five categories and adaptive mutation | VERIFIED | category/strategy tests and actual follow-up |
| Budgets, denial, cancellation and recovery | VERIFIED | tests and controlled Docker error/cancel checks |
| Real Gemini native structured output | VERIFIED | provider, application and Docker checks |
| Docker persistence | VERIFIED | actual restart and exact state/hash comparison |
| Authorized positive/negative E2E | VERIFIED | explicitly synthetic positive, negative scenario |
| Components 5/6 | VERIFIED (2026-10-25) | approvals suite, report suite, Docker and real-benchmark-image checks above |
| Full LangGraph runtime/checkpointer | OUT OF SCOPE | durable minimal orchestration interface (SQLite checkpoints) instead |

No real-world vulnerability discovery, calibrated confidence, full human approval
UI, multi-host SQLite deployment or automatic replay of uncertain requests is
claimed. All five mutation strategies have independent tests; model failure
branches use test doubles in addition to separate real-provider verification.

## Follow-up: Components 5 and 6, and real benchmark-image verification (2026-10-25)

Status: **Components 5 and 6 now VERIFIED**, in Docker and against the real
benchmark container. The "OUT OF SCOPE" row above for Components 5/6 is
superseded by this entry; full LangGraph adoption remains out of scope (see
docs/EXECUTION.md, "there was no existing LangGraph runtime").

Commands executed and results, from repository root:

```powershell
.\.venv\Scripts\python.exe -B -m pytest tests -q
.\.venv\Scripts\python.exe -B -m demo.run --output reports/demo.json
.\.venv\Scripts\python.exe -B -m demo.prepare_docker
docker compose build
docker compose up -d --wait --wait-timeout 120
.\.venv\Scripts\python.exe -B -m demo.docker_verify --output reports/docker-verify.json
docker compose restart executor interpreter report
.\.venv\Scripts\python.exe -B -m demo.docker_verify --restart-check --output reports/docker-verify.json
docker pull monisha117/penagent-target-env:latest
docker run -d --name penagent-testbed -p 18001:3000 -p 18002:8000 -p 18003:8080 monisha117/penagent-target-env:latest
.\.venv\Scripts\python.exe -B -m demo.testenv_verify --output reports/testenv-verify.json
```

- New suite including `tests/test_approvals.py` (10 cases) and
  `tests/test_report.py` (5 cases): **127 passed**. `demo.run` unchanged: 3
  probes, CONFIRMED_VULNERABILITY/STRONG_SIGNAL/NEGATIVE.
- Five Docker images built (`sis`, `hgs`, `executor`, `interpreter`, `report`);
  six containers healthy (`fixture` makes six). A real `compose.yaml` bug was
  found and fixed: a service on only the `internal: true` `control` network
  never gets its published host port bound by this Docker Engine, even with an
  explicit `ports:` entry -- `report` needed `provider_egress` too, like
  `executor`/`interpreter`, despite making no outbound calls itself.
- `demo.docker_verify`: **PASSED**. Component 5's approve path was exercised
  inside the main exploratory audit (`op_fixture_denied` is marked destructive
  for this run only); the chain reliably completes because the now-approved,
  really-executed 403 supplies its own NEGATIVE evidence. Component 5's deny
  path and Component 6's report (2 findings, valid CVSS v3.1 vectors,
  `GET /v1/audits/{audit}/report`) were exercised separately. `--restart-check`
  after restarting executor/interpreter/report: **PASSED**, identical state.
- A real, pre-existing HGS/C2 characteristic was found while debugging this:
  `GET /v1/queue/{target}` lists the whole generated hypothesis batch, not the
  remaining queue, so it cannot predict what `/next` (used internally by
  `/run`) pops next. `demo.docker_verify`'s main loop no longer relies on it
  for anything beyond a best-effort skip of the deliberate-500 hypothesis.
- `images/README.md` names `monisha117/penagent-test-env`; the image actually
  published under that account is `monisha117/penagent-target-env` (the
  documented name fails to pull -- "repository does not exist"). Corrected in
  place, along with DVWS's documented stack/paths (it is FastAPI with
  `/openapi.json`/`/health`, not Express/Svelte with `/api-docs`).
- `demo.testenv_verify` against the real, running container: **PASSED**. Juice
  Shop root and SREBench-API `/health` both reachable (HTTP 200, WEAK_SIGNAL --
  no operator expectation configured for either; this is a reachability check,
  not vulnerability discovery). DVWS's real, live, unauthenticated
  `/api/v1/debug/env` returns a database connection string and a JWT signing
  secret; with a configured `Expectation.protected_fields`, C4 correctly
  classified it STRONG_SIGNAL, and C6's `request_summary` for it was confirmed
  to carry only a body hash, never the raw secret values. Component 5's gate
  was exercised against a real, confirmed-destructive live action (`DELETE
  /api/v1/admin/maintenance/purge-cache`, response `{"status":"cache_purged"}`,
  not a mock): approved once (replayed and executed for real) and denied once
  (blocked, never sent).
- This did not ingest SREBench-API's or DVWS's full OpenAPI surface through C1,
  did not drive HGS's autonomous hypothesis generation against the real
  images (it used a hand-built graph/hypothesis per target, the same pattern
  `demo.juice_check` already uses), and did not attempt SREBench-API's 20
  scenarios or DVWS's documented OWASP API Top 10 coverage. That remained
  deferred evaluation/benchmark work -- completed in the follow-up below.

## Full evaluation run, operator UI, and paper-ready results (2026-10-26)

Status: the deferred evaluation/benchmark work above is now done (minus
Burp Suite/OWASP ZAP/PentestGPT baseline comparisons, which stay explicitly
deferred by agreement). Full results, metrics, and honest discussion of
limitations: [docs/RESULTS.md](RESULTS.md). Summary:

- `demo/run_evaluation.py` drives real C1 ingestion + real C2 hypothesis
  generation + C3/C5/C4 execution (autonomous mode, empty bindings, no
  ground-truth hints) and a separate guided mode (hypotheses built directly
  from `demo/benchmark-data/ground_truth_chains.json`) against all three real targets.
  `demo/evaluate.py` scores both against ground truth with the paper's
  Section 6.2 metrics -- replacing the container's own `/app/datasets/evaluate.py`,
  found to be non-functional (loads the ground truth, never compares
  anything against it; every finding counts as a match unconditionally).
- 134 tests pass total, including new `tests/test_evaluate.py` (7 cases) and
  a new `GET /v1/audits` list endpoint (`Store.list_audits`) the UI needed.
- **Guided mode** (tests execution/classification/approval/report fidelity,
  not discovery): DVWS 80% TPR (4/5, 0% FPR), SREBench-API 100% TPR (2/2),
  Juice Shop 33% TPR (1/3, the other two time-boxed out or scored
  STRONG_SIGNAL by design). One finding (Juice Shop's admin-registration
  bypass) was independently confirmed by Juice Shop's own
  `GET /api/Challenges` tracker flipping `solved: false -> true`.
- **Autonomous mode**: 0% TPR on all three targets -- a specific, reproducible
  finding, not a crash. Root causes found and documented in detail in
  `docs/RESULTS.md`: C4's mutation-discovery only recognizes the synthetic
  fixture's own literal JSON hint keys; HGS's heuristic planner never
  supplies a usable concrete value for a path/body parameter, so any
  parameterized hypothesis is rejected before it reaches the target; and
  `Expectation.owasp_categories` requires an exact string match against
  HGS's own taxonomy, which differs from the ground truth's. Only
  parameter-free GET endpoints were autonomously reachable, and both were
  found (DVWS `/debug/env`, Juice Shop `/rest/admin/application-configuration`),
  correctly classified STRONG_SIGNAL.
- A new operator dashboard, `ui/` (static HTML/CSS/vanilla JS, no build
  step), was built and manually verified against the live stack: audits
  list/create, a live evidence timeline, a Component 5 approvals inbox, a
  Component 6 report view. CORS was added to C3/C6 (`install_cors` in
  `penagent_common/api.py`) for this; it is Bearer-token-gated the same as
  every other route, so CORS only enables the browser fetch, not a new
  trust boundary.

## Baseline, live exploration UI, follow-up (2026-10-26, same day)

- `demo/baseline_pentestgpt.py` implements the paper's Section 6.3 PentestGPT
  baseline (prompt-only reasoning given the spec, no execution) using local
  Ollama models (`llama3.2:3b`, `phi3:latest`, `gemma3:4b`) in place of
  GPT-4, scored with the same `demo/evaluate.py` and ground truth as
  PenAgent's own runs. Full results, and the key finding that TPR alone is
  misleading without FPR (baseline FPR 20-60%, PenAgent 0%): docs/RESULTS.md.
- A real evaluator bug was found and fixed while building this: category
  matching only accepted an exact `"APIn:"` numeric-prefix string; a model
  given the exact taxonomy to copy still dropped the prefix. Replaced with
  keyword-based canonicalization (`demo/evaluate.py::_owasp_prefix`),
  verified not to change any of PenAgent's own already-recorded guided/
  autonomous numbers, with a new regression test
  (`test_match_findings_category_keyword_matches_dropped_numeric_prefix`).
- The UI gained an **Explore** tab: a live endpoint map (C1's graph, nodes
  colored by latest classification) plus a scrolling activity feed -- and
  `demo/configure_live_targets.py` + `demo/live_demo.py` let it watch a real,
  paced exploration of DVWS/SREBench-API/Juice Shop (not only the synthetic
  fixture), verified live end-to-end including a Component 5 approval
  pause-and-resume captured mid-run through the real HTTP API.
- 135 tests pass (one new evaluator regression test).

## Juice Shop ground-truth expansion, multi-stage PentestGPT, autonomous mode dropped (2026-10-27)

- Benchmarked PenAgent and both baselines against all six Ollama models
  present locally (`ollama list`), not a curated subset.
- Added a new `Expectation.forbidden_substrings` mechanism
  (`penagent_common/config.py`, `c4-interpreter/interpreter/evidence.py`) so
  C4 can classify text-body (non-JSON) disclosures as CONFIRMED/STRONG, not
  just JSON-field-path matches; `c6-report/report/synth.py`'s CVSS scoring
  updated to score these as real confidentiality impact. New tests in
  `tests/test_interpreter.py`.
- Expanded Juice Shop's ground truth from 3 to 9 live-verified
  vulnerabilities (`demo/benchmark-data/ground_truth_chains.json`), each
  exercised through a real session-chained attack (register -> login ->
  reuse token) in `demo/run_evaluation.py`'s `GUIDED_CHAINS`. Juice Shop
  guided TPR improved from 33% (1/3) to 77.8% (7/9), 0% FPR maintained.
  Overall guided aggregate across all 3 targets: TPR 85.9%, Precision 100%,
  F1 92.1% (up from a prior TPR 71.1%/F1 79.6%).
- Found and fixed a real evaluator bug while expanding ground truth:
  `demo/evaluate.py`'s directory-prefix fallback let two different static
  files in the same directory cross-match the same finding, which would
  have double-credited one real finding as two. Fixed with a targeted guard
  and a new regression test.
- Implemented `demo/pentestgpt.py`, a more faithful multi-stage PentestGPT
  reproduction (Reasoning stage builds a Pentesting Task Tree, Generation
  stage drills into each sub-task), benchmarked across all six models
  alongside the existing single-shot baseline. Honest finding: structuring
  the reasoning into a task tree does not uniformly beat a single prompt --
  it helps some models (Gemma 2, Gemma 3 4B) and hurts others (Llama 3.2,
  Phi-3, Gemma 3 1B). Full comparison: docs/RESULTS.md.
- Per instruction, dropped fully-autonomous zero-hint discovery mode
  entirely from `demo/run_evaluation.py`, `demo/explore_run.py`,
  `demo/export_ui_data.py`, `demo/live_demo.py`, `demo/configure_live_targets.py`
  and the operator console -- it had consistently scored 0% TPR for the
  specific, already-documented reasons above, and repeating that result on
  every further run added no new information. The finding itself remains
  recorded in this document's 2026-10-26 entries above, not erased.
- 144 tests pass (four new interpreter tests for `forbidden_substrings`, one
  new evaluator regression test).
