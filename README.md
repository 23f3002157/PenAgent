# PenAgent

PenAgent is an authorized, API-spec-driven penetration testing agent. It ingests
an OpenAPI spec, plans attack hypotheses across the OWASP API Top 10, executes
real HTTP probes against the target, classifies every response as evidence,
pauses for human approval before anything destructive, and assembles a
CVSS-scored audit report — as JSON or a rendered PDF. Six components, one
pipeline, nothing skipped.

Run against three real benchmark targets — DVWS, SREBench-API and OWASP Juice
Shop — PenAgent has: flagged DVWS's live, unauthenticated `/api/v1/debug/env`
leak (real DB credentials and a JWT secret) as `STRONG_SIGNAL`; approved and
executed a genuinely destructive cache-purge through its Component 5 gate,
and separately denied one; reached 80% / 100% / 33% true-positive rate against
DVWS / SREBench-API / Juice Shop's documented exploit chains once pointed at a
known attack path; and, let loose with no curation across every real route
Juice Shop exposes (46 of them, read directly off the running container),
solved three challenges independently confirmed by Juice Shop's own built-in
tracker — not PenAgent's self-grading.

See the [repository audit](docs/AUDIT.md), [execution guide](docs/EXECUTION.md),
[step-by-step walkthrough](docs/WALKTHROUGH.md) (run it and watch what it
decides, with real example output), [research-paper compliance map](docs/COMPLIANCE.md),
[verification report](docs/VERIFICATION.md), and [evaluation results](docs/RESULTS.md)
(real TPR/FPR/CVSS-accuracy against DVWS, SREBench-API and Juice Shop, plus the
full-surface exploration run — also in [`reports/PenAgent_Results.xlsx`](reports/PenAgent_Results.xlsx))
for detailed documentation. [`ui/`](ui/README.md) is the operator console: live
audits, a clickable endpoint map, and a dashboard of every result above.

## Components and request flow

| Component | Role | Default local address |
|---|---|---|
| 1: SIS | Ingest specifications and persist endpoint graphs | http://127.0.0.1:9001 |
| 2: HGS | Generate and rank hypotheses from the endpoint graph | http://127.0.0.1:9002 |
| 3: Executor | Validate and execute authorized probes; parse and store evidence | http://127.0.0.1:9003 |
| 4: Interpreter | Classify evidence and propose bounded mutations | http://127.0.0.1:9004 |
| 5: Approval gate | Pause non-safe actions for an operator to approve/deny/timeout | part of Component 3 |
| 6: Report | Assemble stored evidence into a CVSS-scored audit report (JSON and PDF) | http://127.0.0.1:9005 |

```text
C1 endpoint graph -> C2 ranked hypotheses -> C3 validated HTTP execution
                                               |
                                 non-safe action -> C5 approval gate -> approve/deny/timeout
                                               |
                                      persisted response evidence
                                               |
                                      C4 interpretation
                                               |
                              validated mutation -> C3 -> C4
                                               |
                              significant evidence -> C2 replanning
                                               |
                                   C6 audit report, JSON or PDF (on demand)
```

Service communication uses HTTP. C3/C4 share encrypted, audit-scoped SQLite state
for session references, evidence, budgets and workflow progress; C6 reads that
same state read-only. Component 5 lives inside C3 as the approval gate described
above, not as a separate network service.

## Operator console

[`ui/`](ui/README.md) is a dependency-free HTML/CSS/JS dashboard — no build step,
no framework — with three views:

- **Audits** — create and watch a live audit: a clickable endpoint map colored
  by classification, the probe-by-probe evidence timeline, Component 5's
  approval inbox, and the CVSS-scored report with a one-click PDF download.
  A guided-run panel drives real probes against DVWS/Juice Shop from the
  browser itself.
- **Exploration** — every real route DVWS and Juice Shop expose, run and
  graphed: a clickable node map, a status-code breakdown (protected / exposed
  / crashed), a per-resource-area chart, and Juice Shop's own challenge
  tracker confirming what got solved.
- **Baselines & Results** — the scored evaluation: PenAgent (autonomous and
  guided) against three local Ollama models running a prompt-only baseline,
  per target, with the full metrics table.

## Repository layout

| Path | Purpose |
|---|---|
| `c1-spec-ingestion/` | Spec ingestion service; [service README](c1-spec-ingestion/README.md) |
| `c2-hypothesis-gen/` | Hypothesis planning service; [service README](c2-hypothesis-gen/README.md) |
| `c3-executor/` | Executor service and Dockerfile; also hosts Component 5's approval gate |
| `c4-interpreter/` | Interpretation/mutation service and Dockerfile |
| `c6-report/` | Audit-report service and Dockerfile; renders both JSON and PDF |
| `penagent_common/` | Shared schemas, policy, configuration, authentication and persistence |
| `tests/` | Unit, contract, integration and recovery tests |
| `demo/` | Runnable evaluation, exploration, local fixture, and Docker/Gemini/Ollama tooling |
| `docs/` | Repository audit, execution guide, walkthrough, research-paper compliance, verification, and evaluation results |
| `ui/` | Operator console (static HTML/CSS/JS, no build step) |
| `images/` | Test-environment documentation |
| `compose.yaml` | Five-service deployment plus the isolated verification fixture |
| `config.example.json` | Settings template with no authorized targets |
| `.env.example` | Credential-free environment template |
| `runtime/`, `reports/` | Generated local state and run output; ignored by Git except the tracked `reports/PenAgent_Results.xlsx` results workbook |
| `penagent_execution.egg-info/` | Generated pip package metadata; ignored by Git |

`tests/` covers individual behaviors and integration cases automatically; `demo/`
runs complete workflows and execution traces through real HTTP services, and the
Compose verification deployment depends on `demo/fixture_app.py`. A production
deployment excludes the verification fixture and demo utilities.

The package name in `pyproject.toml` is `penagent-execution`, so an editable pip
installation creates `penagent_execution.egg-info/` — installation metadata,
regenerated on reinstall, not another service.

## Local installation and tests

Requirements: Python 3.11+; Docker Engine and Compose for container verification.
Run commands from this directory, containing `pyproject.toml` and `compose.yaml`.
The examples below use Windows PowerShell.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -B -m pytest tests -q
.\.venv\Scripts\python.exe -B -m demo.run --output reports/demo.json
```

The deterministic demonstration starts all four FastAPI apps on temporary loopback
ports and shuts them down afterward. It needs no Gemini key or external target,
and covers a negative response and an explicitly simulated positive case.

Existing service regression suites run separately, since both contain a Python
package named `tests`:

```powershell
.\.venv\Scripts\python.exe -B -m pytest c1-spec-ingestion/tests -q
.\.venv\Scripts\python.exe -B -m pytest c2-hypothesis-gen/tests -q
```

## Docker setup

```powershell
.\.venv\Scripts\python.exe -B -m demo.prepare_docker
docker compose build
docker compose up -d --wait --wait-timeout 120
.\.venv\Scripts\python.exe -B -m demo.docker_verify
```

Preparation creates ignored `.env` service credentials, `runtime/docker.json`
and persistent data directories. Existing configuration and populated keys are
preserved. Retain the state encryption key to read existing encrypted audits.

Compose publishes C1-C4 and C6 on loopback ports 9001-9005 by default. Host ports
can be changed using `SIS_HOST_PORT`, `HGS_HOST_PORT`, `EXECUTOR_HOST_PORT`,
`INTERPRETER_HOST_PORT` and `REPORT_HOST_PORT` in `.env`. The synthetic fixture
has no published host port. Application services join the control and bridge
networks; the fixture and C6 (read-only, no outbound calls) join only the
internal control network.

### Running against the real benchmark targets

```powershell
docker run -d --name penagent-testbed -p 18001:3000 -p 18002:8000 -p 18003:8080 monisha117/penagent-target-env
.\.venv\Scripts\python.exe -B -m demo.configure_live_targets
docker compose restart executor interpreter report
```

Then, the full scored evaluation and the unscored full-surface exploration:

```powershell
.\.venv\Scripts\python.exe -B -m demo.run_evaluation --output reports/eval-final
.\.venv\Scripts\python.exe -B -m demo.explore_run --output reports/explore
.\.venv\Scripts\python.exe -B -m demo.export_ui_data
```

`demo.run_evaluation` scores PenAgent (autonomous and ground-truth-guided)
against DVWS, SREBench-API and Juice Shop's documented exploit chains — see
[docs/RESULTS.md](docs/RESULTS.md). `demo.explore_run` runs every real route
each target exposes with no curation and no scoring — every DVWS route, and
every Juice Shop route read directly off the live container — auto-approving
Component 5 for this disposable, authorized target, and diffing Juice Shop's
own `/api/Challenges` tracker before and after. `demo.export_ui_data` exports
both runs, plus the Ollama baseline comparison, to `ui/data/` for the operator
console's Exploration and Baselines views.

## Optional Gemini integration

Configure `GOOGLE_API_KEY` or `GEMINI_API_KEY` locally in the ignored `.env` file.
`GOOGLE_API_KEY` takes precedence. Never commit the key. Verify an accessible model:

```powershell
.\.venv\Scripts\python.exe -B -m demo.gemini_check --model gemini-3.1-flash-lite
```

After a successful check, set these non-secret selections in `.env`:

```dotenv
GEMINI_MODEL=gemini-3.1-flash-lite
PENAGENT_LLM_PROVIDER=gemini
```

Apply the environment and run the container integration:

```powershell
docker compose up -d --wait --wait-timeout 120
.\.venv\Scripts\python.exe -B -m demo.docker_verify --require-gemini --output reports/docker-gemini.json
```

C4 uses `langchain-google-genai` native structured output. The model receives
filtered evidence predicates and approved choices, without credentials or arbitrary
target response text. Its recommendation selects a validated candidate; deterministic
evidence and authorization rules remain authoritative. Provider errors are sanitized,
calls/timeouts/retries/output tokens are bounded, and tracing is disabled for calls.

## Optional: local Ollama baseline

`demo.baseline_pentestgpt` runs the paper's own PentestGPT-style baseline —
the same OpenAPI spec, pure language reasoning, no execution — against any
locally-installed Ollama model, to isolate the value of PenAgent's
execution-and-feedback loop:

```powershell
ollama pull llama3.2:3b
.\.venv\Scripts\python.exe -B -m demo.baseline_pentestgpt --model llama3.2:3b --output reports/baseline-final
```

Other utilities:

| Command module | Purpose |
|---|---|
| `demo.gemini_application` | Complete temporary TCP workflow with actual Gemini calls |
| `demo.juice_check --url <authorized-origin>` | Supplementary read-only C3/C4 root request to an explicitly authorized target |
| `demo.docker_verify --restart-check --output reports/docker-gemini.json` | Compare saved state/evidence after restarting C3/C4/C6 |
| `demo.testenv_verify --output reports/testenv-verify.json` | C3→C5→C4→C6 smoke check against the real `monisha117/penagent-target-env` container (see [images/README.md](images/README.md)) |
| `demo.run_evaluation --output reports/eval-final` | Scored evaluation: autonomous + ground-truth-guided, all 3 real targets |
| `demo.explore_run --output reports/explore` | Unscored full-surface run: every real route on DVWS and Juice Shop |
| `demo.export_ui_data` | Exports evaluation, exploration and baseline results to `ui/data/` |

## Component 3, 4, 5 and 6 APIs

C3, C4 and C6 expose `/docs`, `/openapi.json`, `/health` and `/ready`. C3 and C6's
business routes require an operator Bearer token from `PENAGENT_API_TOKENS`; C4's
business routes require `PENAGENT_SERVICE_TOKEN`.

| Service | Method and route | Input / output |
|---|---|---|
| C3 | POST `/v1/audits` | `AuditCreate` -> audit ID and status |
| C3 | GET `/v1/audits/{audit}` | Audit status and counters |
| C3 | POST `/v1/audits/{audit}/probes` | Existing C2 hypothesis plus `Probe` -> `ExecutionResult` |
| C3 | GET `/v1/audits/{audit}/probes/{probe}` | Stored result and interpretation |
| C3 | GET / PUT `/v1/audits/{audit}/state` | Read state / apply `StateWrite` |
| C3 | GET `/v1/audits/{audit}/evidence` | Redacted execution trace |
| C3 | POST `/v1/audits/{audit}/run` | Step-number-to-binding map -> workflow outcome |
| C3 | POST `/v1/audits/{audit}/guided-step` | One exact op + binding -> execute and interpret in a single call (drives the operator console) |
| C3 | POST `/v1/audits/{audit}/cancel` | Cancel audit |
| C3 | GET `/v1/tools` | Four strict tool schemas |
| C3 (C5) | GET `/v1/audits/{audit}/approvals` | Pending/decided approval records |
| C3 (C5) | POST `/v1/audits/{audit}/approvals/{probe}` | `ApprovalDecision` (approve/deny + reason) -> `ExecutionResult` |
| C4 | POST `/v1/audits/{audit}/interpret` | `{owner, probe_id}` -> `Interpretation` |
| C4 | POST `/v1/audits/{audit}/mutations` | `{owner, probe_id}` -> `Mutation` or null |
| C6 | GET `/v1/audits/{audit}/report` | -> `AuditReport` (CVSS-scored findings + observations) |
| C6 | GET `/v1/audits/{audit}/report.pdf` | -> the same report, rendered as a PDF |

C3 exposes `http_request`, `parse_response`, `read_session_state` and
`write_session_state` through validated function-tool definitions. Audit identity
and graph operation are bound by the host, outside model arguments. State tools
return redacted references; model-authored updates cannot fabricate credentials.

Interpretation categories are `CONFIRMED_VULNERABILITY`, `STRONG_SIGNAL`,
`WEAK_SIGNAL`, `NEGATIVE` and `ERROR_CRASH`. Confirmation requires configured
security predicates and supporting evidence; status codes alone do not prove a flaw.

A non-safe operation (`risk` other than `safe`, `DELETE`, a semantically dangerous
path, or a risky payload field) is reserved as `awaiting_approval` instead of being
denied outright. The operator reviews it with `GET /v1/audits/{audit}/approvals`
and resolves it with `POST .../approvals/{probe}`; an approval replays exactly the
stored request (nothing about it can change at decision time, and the bypass never
applies to any other probe), a denial blocks it permanently, and an unresolved
request auto-skips after `approval_timeout` (default 1800s). C6's report is
callable at any point and reflects whatever evidence has been collected so far;
`CONFIRMED_VULNERABILITY`/`STRONG_SIGNAL` become scored findings (deterministic
CVSS v3.1, never LLM-assigned), `WEAK_SIGNAL` becomes an observation, and
`ERROR_CRASH` becomes an unscored operational issue.

## Configuration, safety and persistence

`PENAGENT_CONFIG` selects the JSON configuration. Settings cover exact authorized
target origins/operations, service URLs, timeouts, response limits, concurrency,
rate limits, probe/mutation/depth/LLM budgets and maximum audit duration.
`PENAGENT_STATE_KEY` encrypts shared audit state. The example config authorizes
no targets; the Docker preparation utility authorizes only its synthetic fixture.

- Targets must use explicitly authorized numeric-IP origins and known graph operations.
  Metadata destinations, unauthorized destinations and all redirects are rejected.
- Credentials use approved audit-scoped state references. Public evidence hides
  raw secrets and arbitrary response contents; evidence hashes preserve provenance.
- Header, parameter, body, authentication-context and observed-state mutations
  must pass schema, authorization, risk, ancestry, deduplication and budget checks.
- Potentially destructive or approval-required actions pause at the Component 5
  gate for an authenticated human operator to approve, deny, or let time out.
  A model cannot approve them, and an approval never widens scope beyond the
  one already-reserved probe it was granted for.
- A 5xx conservatively halts that audit — a deliberate "something's wrong, stop
  for a human" rule, not proof of exploitation. Cancellation and persistent
  budgets prevent continued execution.
- State, checkpoints and evidence survive restart. Unknown request outcomes are
  not automatically replayed.
- HGS queues are target-scoped; independent concurrent audits should not share a
  single target queue. Confidence scores are rule-based, not statistically calibrated.

`.gitignore` excludes local secrets, virtualenvs, package metadata, bytecode/caches,
databases, runtime state, logs, coverage and generated reports (except the tracked
results workbook). `.env.example` remains available as a safe template.

## Verification status

Last executed verification: **2026-10-26**. Host Python 3.12.8; Docker Desktop
28.5.2.

| Check | Result |
|---|---|
| Unit/contract/integration/recovery/approval/report test suite | 139 passed |
| Interpreter combined statement/branch coverage | 88% |
| Deterministic four-service TCP demonstration | Passed |
| Five Docker builds and six-container deployment (sis, hgs, executor, interpreter, report, fixture) | Passed |
| Docker C1-C4 flow with real Gemini | Passed |
| Component 5 approve/deny gate, live in Docker | Passed |
| Component 6 report generation (JSON and PDF), live in Docker | Passed — CVSS v3.1 vectors; a real 2-page PDF rendered from live findings |
| State and evidence integrity after C3/C4/C6 restart | Passed |
| Reachability of all 3 real benchmark targets (Juice Shop, SREBench-API, DVWS) | Passed |
| C3→C5→C4→C6 against the 3 real targets | Passed — DVWS's live, unauthenticated `/api/v1/debug/env` (real DB credentials + a JWT secret) correctly flagged `STRONG_SIGNAL`; Component 5 approved and executed, and separately denied, a real destructive DELETE on DVWS |
| Scored evaluation against documented exploit chains, all 3 real targets | Guided true-positive rate 80% / 100% / 33% (DVWS / SREBench-API / Juice Shop) — full methodology in [docs/RESULTS.md](docs/RESULTS.md) |
| Full-surface exploration, every real route, no curation (`demo.explore_run`) | 46/46 Juice Shop routes and 6/6 DVWS routes executed; 5 of 6 DVWS routes flagged `STRONG_SIGNAL`; 3 Juice Shop challenges solved, independently confirmed by its own `/api/Challenges` tracker |
| Operator console, all 3 views, against the live stack | Audits, Exploration and Baselines & Results confirmed against real API responses |
