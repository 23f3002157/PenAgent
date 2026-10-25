# PenAgent

PenAgent combines endpoint discovery, hypothesis planning, authorized HTTP probes,
evidence-based response interpretation, a human approval gate for non-safe actions
and audit report synthesis. Components 3-6 extend the existing Component 1 and 2
microservices while preserving their public HTTP contracts. Their SQLite connection
helpers also close handles explicitly to fix a resource leak.

See the [repository audit](docs/AUDIT.md), [execution guide](docs/EXECUTION.md),
[step-by-step walkthrough](docs/WALKTHROUGH.md) (run it and watch what it
decides, with real example output), [research-paper compliance map](docs/COMPLIANCE.md)
and [verification report](docs/VERIFICATION.md) for detailed documentation.

## Components and request flow

| Component | Role | Default local address |
|---|---|---|
| 1: SIS | Ingest specifications and persist endpoint graphs | http://127.0.0.1:9001 |
| 2: HGS | Generate and rank hypotheses from the endpoint graph | http://127.0.0.1:9002 |
| 3: Executor | Validate and execute authorized probes; parse and store evidence | http://127.0.0.1:9003 |
| 4: Interpreter | Classify evidence and propose bounded mutations | http://127.0.0.1:9004 |
| 5: Approval gate | Pause non-safe actions for an operator to approve/deny/timeout | part of Component 3 |
| 6: Report | Assemble stored evidence into a CVSS-scored audit report | http://127.0.0.1:9005 |

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
                                   C6 audit report (on demand)
```

Service communication uses HTTP. C3/C4 share encrypted, audit-scoped SQLite state
for session references, evidence, budgets and workflow progress; C6 reads that
same state read-only. The minimal orchestrator persists transitions; it is not a
full LangGraph application or a LangGraph checkpointer. Component 5 lives inside
C3 as the approval gate described above, not as a separate network service.

## Repository layout

| Path | Purpose |
|---|---|
| `c1-spec-ingestion/` | Existing ingestion service; [service README](c1-spec-ingestion/README.md) |
| `c2-hypothesis-gen/` | Existing planning service; [service README](c2-hypothesis-gen/README.md) |
| `c3-executor/` | Production executor service and Dockerfile; also hosts Component 5's approval gate |
| `c4-interpreter/` | Production interpretation/mutation service and Dockerfile |
| `c6-report/` | Production audit-report service and Dockerfile |
| `penagent_common/` | Shared schemas, policy, configuration, authentication and persistence |
| `tests/` | Automated unit, contract, integration and recovery tests |
| `demo/` | Runnable integration verification, local HTTP fixture and Docker/Gemini checks |
| `docs/` | Repository audit, execution guide, step-by-step walkthrough, research-paper compliance and verification report |
| `images/` | Existing test-environment documentation and images |
| `compose.yaml` | Five-service deployment plus the isolated verification fixture |
| `config.example.json` | Settings template with no authorized targets |
| `.env.example` | Credential-free environment template |
| `runtime/`, `reports/` | Generated local state and verification output; ignored by Git |
| `penagent_execution.egg-info/` | Generated pip package metadata; ignored by Git |

`tests/` checks individual behaviors and integration cases automatically. `demo/`
provides runnable complete workflows and execution traces through real HTTP
services. Integration tests also reuse `demo/harness.py`. The current Compose
verification deployment depends on `demo/fixture_app.py`; removing `demo/` without
adjusting Compose and tests will break that setup. A production deployment can
exclude the verification fixture and utilities after adjusting those dependencies.

The package name in `pyproject.toml` is `penagent-execution`, so an editable pip
installation creates `penagent_execution.egg-info/`. It is installation metadata,
not another service; reinstalling the package regenerates it.

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
ports and shuts them down afterward. It needs no Gemini key or external target.
It covers a negative response and an explicitly simulated positive case.
No benchmarks, benchmark specifications, ground truth or datasets are created.

Existing service regression suites must run separately because both contain a
Python package named `tests`:

```powershell
.\.venv\Scripts\python.exe -B -m pytest c1-spec-ingestion/tests -q
.\.venv\Scripts\python.exe -B -m pytest c2-hypothesis-gen/tests -q
```

Some existing cases require authoritative external specs, datasets and target
environments absent from this checkout. See the verification status below.

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
internal control network. C1/C2 retain their existing unauthenticated APIs, so
preserve the trusted local boundary.

## Optional Gemini integration

Configure `GOOGLE_API_KEY` or `GEMINI_API_KEY` locally in the ignored `.env` file.
`GOOGLE_API_KEY` takes precedence. Never commit the key. Verify an accessible model:

```powershell
.\.venv\Scripts\python.exe -B -m demo.gemini_check --model gemini-3.1-flash-lite
```

That model was verified with the configured account; availability can differ by
account. Catalogue listing alone does not prove that generation works. After a
successful check, set these non-secret selections in `.env`:

```dotenv
GEMINI_MODEL=gemini-3.1-flash-lite
PENAGENT_LLM_PROVIDER=gemini
```

Apply the environment and run the actual container integration:

```powershell
docker compose up -d --wait --wait-timeout 120
.\.venv\Scripts\python.exe -B -m demo.docker_verify --require-gemini --output reports/docker-gemini.json
```

C4 uses `langchain-google-genai` native structured output. The model receives
filtered evidence predicates and approved choices, without credentials or arbitrary
target response text. Its recommendation selects a validated candidate; deterministic
evidence and authorization rules remain authoritative. Provider errors are sanitized,
calls/timeouts/retries/output tokens are bounded, and tracing is disabled for calls.
Real provider verification consumes the configured account's quota.

Other utilities:

| Command module | Purpose |
|---|---|
| `demo.gemini_application` | Complete temporary TCP workflow with actual Gemini calls |
| `demo.juice_check --url <authorized-origin>` | Supplementary read-only C3/C4 root request to an explicitly authorized target |
| `demo.docker_verify --restart-check --output reports/docker-gemini.json` | Compare saved state/evidence after restarting C3/C4/C6 |
| `demo.testenv_verify --output reports/testenv-verify.json` | Smoke check against the real `monisha117/penagent-target-env` container (see [images/README.md](images/README.md)): C3→C5→C4→C6 against Juice Shop, SREBench-API and DVWS |

The restart check requires an existing successful report at the selected path:

```powershell
docker compose restart executor interpreter
.\.venv\Scripts\python.exe -B -m demo.docker_verify --restart-check --output reports/docker-gemini.json
```

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
| C3 | POST `/v1/audits/{audit}/cancel` | Cancel audit |
| C3 | GET `/v1/tools` | Four strict tool schemas |
| C3 (C5) | GET `/v1/audits/{audit}/approvals` | Pending/decided approval records |
| C3 (C5) | POST `/v1/audits/{audit}/approvals/{probe}` | `ApprovalDecision` (approve/deny + reason) -> `ExecutionResult` |
| C4 | POST `/v1/audits/{audit}/interpret` | `{owner, probe_id}` -> `Interpretation` |
| C4 | POST `/v1/audits/{audit}/mutations` | `{owner, probe_id}` -> `Mutation` or null |
| C6 | GET `/v1/audits/{audit}/report` | -> `AuditReport` (CVSS-scored findings + observations) |

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
- A 5xx conservatively halts the audit; it is not proof of exploitation. Cancellation
  and persistent budgets prevent continued execution.
- State, checkpoints and evidence survive restart. Unknown request outcomes are
  not automatically replayed. Shared multi-host SQLite deployment is not claimed.
- HGS queues are target-scoped; independent concurrent audits should not share a
  single target queue. Confidence scores are rule-based, not statistically calibrated.

`.gitignore` excludes local secrets, virtualenvs, package metadata, bytecode/caches,
databases, runtime state, logs, coverage and generated reports. `.env.example`
remains available as a safe template. Ignore rules do not untrack files already
committed in the original repository.

## Recorded verification status

Last executed verification: **2026-10-25**. Host Python 3.12.8; Docker Desktop
28.5.2, Docker Python 3.11. These are recorded results, not a claim that
verification runs whenever this file is edited.

| Check | Recorded result |
|---|---|
| New unit/contract/integration/recovery/approval/report suite | 127 passed |
| Interpreter combined statement/branch coverage | 88% (unchanged by this work) |
| Available C1 / C2 regressions | 6 passed / 8 passed |
| Deterministic four-service TCP demonstration | Passed |
| Actual Gemini native output and application flow | Passed (2026-10-24; not re-run this pass, no key available) |
| Five Docker builds and six-container deployment (sis, hgs, executor, interpreter, report, fixture) | Passed |
| Docker C1-C4 flow with real Gemini | Passed (2026-10-24) |
| Component 5 approve/deny gate, live in Docker (`demo.docker_verify`) | Passed |
| Component 6 report generation, live in Docker (`demo.docker_verify`) | Passed; 2 findings, valid CVSS v3.1 vectors |
| Planner handoff, cancellation and controlled-error halt | Passed |
| State and evidence after C3/C4/C6 restart | Passed |
| Real `monisha117/penagent-target-env` reachability (Juice Shop, SREBench-API, DVWS) | All 3 targets reachable; `images/README.md` corrected (wrong image name, wrong DVWS paths/stack documented) |
| C3→C5→C4→C6 smoke against the 3 real targets (`demo.testenv_verify`) | Passed; DVWS's real, live, unauthenticated `/api/v1/debug/env` (returns DB credentials + a JWT secret) correctly flagged STRONG_SIGNAL; Component 5 approved/executed and denied/blocked a real destructive DELETE on DVWS |

Overall acceptance remains **PARTIALLY COMPLETE**: the full original C1 suite had
6 passes and 5 missing-input/environment failures; C2 had 8 passes and 1 missing
ground-truth failure. Available-only reruns deselected those six blocked cases;
they were not counted as passes. They concern Juice Shop/DVWS specification inputs
and future SREBench specifications/ground truth. No replacement benchmarks or
datasets were created. `demo.testenv_verify` is a reachability/pipeline smoke
check against the three real targets, not a benchmark run: it does not attempt
SREBench-API's 20 scenarios or DVWS's full OWASP API Top 10 coverage, and does
not establish a complete real-world vulnerability inventory.
