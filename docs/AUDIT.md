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
