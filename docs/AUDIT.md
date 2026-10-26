# Repository audit (2026-10-24)

Baseline: c59b8b3d6e5cedf599850fc50f7c4bce33f1c2f4. All source, tests,
READMEs, requirements, Dockerfiles and Postman collections inspected; the six
pages of images/SREBench API.pdf were rendered and visually inspected.
The supplied research paper, especially pages 9–11 and 14–17, governs numbering.

## Existing compatibility matrix

| Service | Endpoint | Request | Response | Consumer | Integration |
|---|---|---|---|---|---|
| SIS | POST /v1/ingest | IngestRequest(target_id,base_url,spec_source?,auth_profile?) | 202 job_id,target_id,status,message | operator | HTTP, poll job |
| SIS | GET /v1/ingest/{job_id} | path | IngestJob | operator | HTTP |
| SIS | GET /v1/graph/{target_id} | path | EndpointGraph | executor | HTTP |
| SIS | GET /v1/graph/{target_id}/attack-surface | path | AttackSurfaceView | HGS | HTTP |
| SIS | POST /v1/graph/{target_id}/augment | AugmentRequest | EndpointGraph | discovery | HTTP |
| SIS | POST /v1/graph/{target_id}/refresh | base_url,spec_source? | RefreshResponse | operator | HTTP |
| HGS | POST /v1/hypotheses/generate | GenerateHypothesesRequest | HypothesisBatch | operator | HTTP |
| HGS | GET /v1/hypotheses/{batch_id} | path | HypothesisBatch | operator | HTTP |
| HGS | GET /v1/queue/{target_id}/next | path | AttackHypothesis or 204 | executor | destructive queue pop over GET |
| HGS | GET /v1/queue/{target_id} | limit? | AttackHypothesis[] | operator | HTTP |
| HGS | POST /v1/hypotheses/{id}/feedback | HypothesisFeedbackRequest | FeedbackResponse | executor | HTTP |
| HGS | POST /v1/events/replan | ReplanEventRequest | HypothesisBatch | executor | HTTP |
| both | GET /health | none | status,service,version | monitoring | HTTP |

SIS: `uvicorn sis.main:app`, port 9001; HGS: `uvicorn hgs.main:app`,
port 9002. Docker Python 3.11; dependencies specify lower bounds, no locks.
Validation environment uses Python 3.13. No existing route authentication,
gateway, LangChain, LangGraph, durable audit checkpoints or session credential
store. SQLite graph and queue stores, optional Redis; HGS knowledge is in memory
and keyed by target, not audit. Existing HTTP errors use FastAPI detail and 404/500.
Graph nodes contain id, method, path, parameters (`in` alias or `location`),
request_body_schema, response_schemas, auth and tags. Steps contain step, op,
method, path, notes, payload_hint. HGS validator enriches method/path from graph.
Heuristic payloads such as alternate_tenant_id are hints, not real IDs.

## Environment and discrepancies

images/README describes one monisha117/penagent-test-env container: host
18001→3000 Juice Shop, 18002→8000 SREBench, 18003→8080 DVWS. MongoDB and
MariaDB are container-loopback only. DVWS documents seeded accounts; no
credentials are inferred for other targets. Reset procedure is not documented
apart from container replacement. No live targets are assumed authorized by
their presence in a document.

The PDF describes logical services 8001–8003 and an older image name; the README
describes the unified target on 18002. Neither proves running topology. Docker
daemon pipes are absent here, including outside sandbox. Specs and datasets
referenced by existing tests are absent. Existing READMEs' Docker build paths
(`spec-ingestion`, `hypothesis-gen`) differ from actual directory names. Their
test-count claims are stale; report actual pytest results. images/README's
`penagent.cli` does not exist. SIS storage advertises Postgres but falls back to
SQLite for non-SQLite URLs. HGS stored-batch target_id derives from an operation
ID; executor must bind target independently. Feedback's triggered_replan flag
does not imply a replan occurred when discovered_state is empty.

## Integration plan

Add distinct C3/C4 FastAPI applications and shared strict schemas. Reuse the
existing SIS/HGS models without editing their contracts. Fetch graphs and queue
over bounded HTTP. Bind execution to operator-configured target/operation rules,
validate schema and explicit dependencies, and persist audit-scoped state and
probe reservations in SQLite. Deny risky operations through an explicit missing
C5 gate. Interpret actual stored evidence using operator-defined security
expectations and validated optional model recommendations. Mutations must pass
the executor again. Add a resumable minimal orchestration interface, not a claim
of a complete LangGraph or report generator. Validate with real local HTTP
services and fixture targets; report unavailable benchmarks separately.

## Final integration follow-up (2026-10-24)

Docker Desktop became available during final integration: Linux Engine 29.4.3,
Compose 5.1.3. All four service images built and the isolated fixture deployment
became healthy. Python 3.11 ran inside images; host tests used Python 3.13.5.
The pre-existing Juice Shop container was started without replacement and its
root endpoint returned HTTP 200. Its existing host port 3000 binding was retained.
No SREBench or DVWS environment, benchmark specification, ground truth or dataset
was created. Their missing historical inputs remain explicit regression blockers.

Only C1's GraphStorage._get_connection and C2's PriorityQueue._get_connection
changed: context managers now close connections in finally after transaction
completion. Real ResourceWarnings and Windows temporary-directory locks motivated
this correction; source tests prove handles close. No public routes or schemas
changed. Shared C3/C4 journal schemas are separate from these legacy stores.

Gemini was integrated using langchain-google-genai 4.4.2 and validated with the
operator-supplied local key and gemini-3.1-flash-lite. Credentials were kept in
ignored .env. The existing HGS heuristic/provider behavior was preserved.

## Components 5 and 6, and real benchmark-image verification (2026-10-25)

Component 5 (human approval gate, inside C3 -- see docs/EXECUTION.md) and
Component 6 (audit report generation, new `c6-report/` service) were implemented.
127 pytest cases pass, including new `tests/test_approvals.py` (10 cases) and
`tests/test_report.py` (5 cases). `python -m demo.run` still passes unchanged
(3 probes, CONFIRMED_VULNERABILITY/STRONG_SIGNAL/NEGATIVE), confirming the
synthetic hermetic path is unaffected.

Docker Desktop 28.5.2 was used. All five images (`sis`, `hgs`, `executor`,
`interpreter`, `report`) built and `docker compose up` brought up all six
containers (plus the synthetic fixture) healthy. A pre-existing `compose.yaml`
bug was found and fixed during this work: a service on only the `control`
network (`internal: true`) never gets its published host port bound by this
Docker Engine, even with an explicit `ports:` entry; `report` needed
`provider_egress` too, matching `interpreter`/`executor`, despite making no
outbound calls itself. `demo.docker_verify` was extended to also check C6's
`/health`/`/ready`, exercise Component 5's approve path (inside the main
exploratory audit, against `op_fixture_denied` marked destructive for this run)
and deny path (a dedicated audit), and confirm C6's report contains the run's
`CONFIRMED_VULNERABILITY` finding with a well-formed CVSS v3.1 vector; it
passed, as did the existing `--restart-check` after restarting
executor/interpreter/report. A real, pre-existing HGS/C2 characteristic was
found along the way: `GET /v1/queue/{target}` lists the whole generated batch,
not the remaining queue, so it cannot be used to predict what `/next` (used
internally by `/run`) will pop next; `demo.docker_verify`'s main loop was made
robust to that rather than relying on it.

The real target image was located and pulled: `images/README.md` names
`monisha117/penagent-test-env`, but the image actually published under that
Docker Hub account is `monisha117/penagent-target-env` (the pull of the
documented name fails with "repository does not exist"); `images/README.md`
was corrected in place. The corrected image was run per that document's
instructions (`-p 18001:3000 -p 18002:8000 -p 18003:8080`). All three targets
were reachable: Juice Shop (real OWASP Juice Shop, HTTP 200 at `/`), SREBench-API
(FastAPI, `/health` healthy, `/scenarios/list` returns its 20 scenarios), and
DVWS (also FastAPI, not the Express/Svelte/MariaDB/MongoDB stack
`images/README.md` describes; real OpenAPI spec at `/openapi.json`, not
`/api-docs` as documented). `demo.testenv_verify` (new) drives C3 ->
Component 5 -> C4 -> Component 6 against these three live targets with a
hand-built graph/hypothesis per target, the same pattern `demo.juice_check`
already uses, rather than a live C1/C2/HGS deployment. It passed: Juice Shop
root and SREBench `/health` both classified WEAK_SIGNAL (no operator
expectation configured for either, intentionally -- this is a reachability
check, not vulnerability discovery); DVWS's `/api/v1/debug/env` -- a real,
live, unauthenticated endpoint that returns a database connection string and a
JWT signing secret -- classified STRONG_SIGNAL against a configured
expectation, with the report's `request_summary` confirmed to carry only a
body hash, never the raw secrets; and Component 5's gate was exercised against
a real, confirmed-destructive live action (`DELETE
/api/v1/admin/maintenance/purge-cache`, which genuinely purges something, not
a mock) -- approved once (replayed and executed for real) and denied once
(blocked, never sent). No SREBench/DVWS benchmark specification, ground truth
or dataset was created, and this did not attempt to discover the 20
SREBench-API scenarios or DVWS's full OWASP API Top 10 coverage; that
evaluation work remained explicitly deferred -- completed in the follow-up
below.

## Full evaluation, operator UI (2026-10-26)

The deferred SREBench-API/DVWS/Juice Shop evaluation and the operator UI were
built. Details and real numbers: docs/RESULTS.md and docs/VERIFICATION.md's
"Full evaluation run" entry. Two findings from this work are worth recording
here specifically because they're about the *evaluation infrastructure
itself*, not about PenAgent:

1. The container's own `/app/datasets/evaluate.py` does not work -- it loads
   ground truth and never compares anything against it. `demo/evaluate.py`
   is a real implementation, unit-tested against synthetic fixtures.
2. The container's `/scenarios/list` live endpoint advertises 20 SREBench
   scenarios, but only 2-3 distinct `endpoint_chain` patterns repeat across
   them with incrementing placeholder numbers; the curated
   `ground_truth_chains.json` gives exactly 2 scenarios with real, concrete,
   independently actionable exploit chains. Evaluation was scored against
   those 2, not a fabricated 20.

A genuine PenAgent-side finding, not an evaluation-infrastructure one: C4's
mutation-discovery (`interpreter/evidence.py`) keys its strategy off literal
JSON field names the project's own synthetic fixture happens to use
(`missing_header`, `invalid_parameter`, etc.); real targets signal the same
information in free text or don't signal it via those exact keys at all, so
autonomous mutation-driven discovery does not yet generalize past the
fixture's own conventions. Recorded as a concrete, scoped follow-up item in
docs/RESULTS.md, not glossed over.
