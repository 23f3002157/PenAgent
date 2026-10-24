# Components 3 and 4

## Architecture

C1 (`sis.main:app`, 9001) → C2 (`hgs.main:app`, 9002) → C3
(`executor.main:app --factory`, 9003) ↔ C4 (`interpreter.main:app --factory`,
9004). All service arrows use actual HTTP. C3/C4 share an encrypted SQLite
audit/evidence journal; configure the same database path and Fernet key.
C1/C2 storage schemas and contracts are unchanged; connection helpers explicitly
close SQLite handles. C4 loads persisted evidence by probe
ID rather than accepting caller-invented responses.

`POST /run` processes one HGS hypothesis, its ordered steps and bounded mutations.
It sends feedback and an explicit HGS replanning event on significant findings.
Call again for the next hypothesis. Empty queue enters REPORTING and exposes
the execution trace. Component 6 report generation and COMPLETE are not claimed.

There was no existing LangGraph runtime. The minimal Workflow persists execution,
interpretation, mutation, replanning and approval-boundary transitions in SQLite.
It is a clean host integration interface, not an installed LangGraph graph or
LangGraph checkpointer. INGESTING and PLANNING belong to C1/C2.

## Installation and start commands

Use Python 3.11+ from the repository root. Validation used Python 3.13; original
Dockerfiles specify 3.11.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
New-Item -ItemType Directory -Force runtime
Copy-Item config.example.json runtime/config.json
$env:PENAGENT_CONFIG = (Resolve-Path runtime/config.json).Path
$env:PENAGENT_STATE_KEY = (.\.venv\Scripts\python.exe -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
$env:PENAGENT_SERVICE_TOKEN = (.\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))')
$operatorToken = (.\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))')
$env:PENAGENT_API_TOKENS = (@{operator=$operatorToken} | ConvertTo-Json -Compress)
```

Retain the generated credentials securely. Both new service terminals need the
same key, machine token, API-token map and configuration. Do not regenerate a
key for existing encrypted audits. Run each command in a separate terminal:

```powershell
.\.venv\Scripts\python.exe -B -m uvicorn sis.main:app --host 127.0.0.1 --port 9001 --no-access-log
.\.venv\Scripts\python.exe -B -m uvicorn hgs.main:app --host 127.0.0.1 --port 9002 --no-access-log
.\.venv\Scripts\python.exe -B -m uvicorn interpreter.main:app --factory --host 127.0.0.1 --port 9004 --no-access-log
.\.venv\Scripts\python.exe -B -m uvicorn executor.main:app --factory --host 127.0.0.1 --port 9003 --no-access-log
```

The four Docker images were built and the actual Compose deployment exercised.
Dockerfiles use repository root as context. `demo.prepare_docker` generates only
ignored local service credentials/configuration, selects a nonoverlapping subnet
and preserves existing keys. Compose publishes C1-C4 on 127.0.0.1:9001-9004;
the synthetic fixture has no published port. Shared bind-mounted encrypted SQLite
state survives service restart. Existing C1/C2 remain unauthenticated; retain the
trusted local boundary. Application services use the internal control network
and a bridge network; the fixture uses only the internal network.

Dependencies reuse FastAPI/Pydantic/httpx; jsonschema validates endpoint schemas,
cryptography encrypts state, python-dotenv loads local settings and
langchain-google-genai provides the maintained Gemini integration.

## Configuration

`PENAGENT_CONFIG` points to a JSON Settings object. Unknown keys and invalid
ranges are rejected. Secrets have no defaults. Environment overrides are
`SIS_URL`, `HGS_URL`, `INTERPRETER_URL`, `PENAGENT_SERVICE_TOKEN`,
`PENAGENT_STATE_KEY`, `PENAGENT_LLM_KEY`, `PENAGENT_API_TOKENS` (JSON principal→token).

| JSON setting | Default | Purpose |
|---|---:|---|
| database | execution.db | Shared SQLite journal |
| targets | {} | Authorized origins and operations |
| sis_url, hgs_url, interpreter_url | empty | Trusted service addresses |
| connect_timeout / read_timeout | 2 / 5 s | Connect and chunk inactivity bounds |
| request_timeout | 15 s | Absolute target request including retry/rate waits |
| service_timeout | 10 s | Absolute interservice bound |
| max_response_size / max_request_size | 262144 / 65536 bytes | Response/request and state limits |
| max_probes | 30 | Atomic per-audit probe reservations |
| max_mutations | 3 | Per-hypothesis mutation reservations |
| max_depth | 6 | Exclusive upper bound on zero-based mutation depth |
| max_llm_calls | 4 | Persistent model-call budget |
| max_duration | 300 s | Audit lifetime including pauses/restarts |
| concurrency | 2 | Shared SQLite network-slot cap |
| requests_per_second | 2 | Shared request-start pacing |
| retries | 1 | Connect-error retries for safe GET/HEAD/OPTIONS only |
| llm_url / llm_model | empty | Optional function-calling provider |
| llm_provider | none | none, gemini or function_calling |
| llm_timeout / llm_retries / llm_max_tokens | 20 s / 1 / 768 | Bounded model call controls |

`config.example.json` authorizes no targets. Example target policy, to merge into
the configuration only after reviewing the actual C1 operation IDs:

```json
{"targets":{"fixture":{"base_url":"http://127.0.0.1:18090","credential_refs":[],"operations":{
  "op_fixture_object":{"method":"GET","path":"/admin/object","risk":"safe",
    "allowed_headers":["X-Test-Context"],"header_variations":{"X-Test-Context":["fixture-only"]},
    "expectation":{"expected_behavior":"Anonymous clients cannot receive tenant-b private data",
      "protected_fields":["private_data"],"signal_fields":["signal"],"forbidden_values":{"owner":"tenant-b"},"requires_anonymous":true}}
}}}}
```

This describes the fixture, not an authorization of a running benchmark. Target
origins currently require **numeric IPs**. Exact scheme/IP/port binding eliminates
DNS rebinding. Resolve/review container IPs outside the agent; target hostnames
are rejected. Metadata/link-local/reserved/mapped IPv6/multicast/unspecified
addresses and Azure/Alibaba special metadata endpoints are rejected even if
configured. All redirects are denied. URL-valued request fields are also checked.
Container localhost is not host localhost; use a reachable explicitly reviewed IP.

Every operation must match the configured ID, method and path and the C1 graph.
Operator rules attest semantic safety. Dangerous path/summary/description terms
override a safe label; reversible/destructive/requires_approval actions enter
AWAITING_APPROVAL and are denied by the Component 5 boundary. No approval API,
30-minute approval UI or human review workflow is implemented. A model cannot
override the boundary. Safe POST/search needs an explicit safe rule too.

## APIs

Both services publish `/docs` and `/openapi.json`. C3 requires the principal's
Bearer token; C4 internal routes require the machine token. Health/readiness are
public and contain no evidence or credentials.

| Service | Method / route | Request | Response |
|---|---|---|---|
| C3 | POST /v1/audits | AuditCreate | 201 audit_id,status |
| C3 | GET /v1/audits/{audit} | — | audit counters/status |
| C3 | POST /v1/audits/{audit}/probes | ExecuteInput(hypothesis,probe) | sanitized ExecutionResult |
| C3 | GET /v1/audits/{audit}/probes/{probe} | — | result,interpretation,status |
| C3 | GET /v1/audits/{audit}/state | — | SessionState, secrets hidden |
| C3 | PUT /v1/audits/{audit}/state | StateWrite | sanitized SessionState |
| C3 | GET /v1/audits/{audit}/evidence | — | redacted trace/transitions |
| C3 | POST /v1/audits/{audit}/run | RunInput(bindings) | workflow outcome |
| C3 | POST /v1/audits/{audit}/cancel | — | cancelled |
| C3 | GET /v1/tools | — | four tool schemas |
| C4 | POST /v1/audits/{audit}/interpret | owner,probe_id | Interpretation |
| C4 | POST /v1/audits/{audit}/mutations | owner,probe_id | Mutation or null |
| both | GET /health | — | healthy,component |
| C3 | GET /ready | — | DB and C1/C2/C4 health or 503 |
| C4 | GET /ready | — | DB health |

Create request:

```json
{"audit_id":"audit-demo","target_id":"fixture","acknowledged_authorization":true}
```

Example `/run` bindings (keys are HGS step numbers):

```json
{"bindings":{"1":{},"2":{"path":{"object_id":{"$state":"object_ids.op_fixture_session.object_id"}},"session_ref":"op_fixture_session.access_token","depends_on":[1]}}}
```

Binding fields: path, query, headers, body, body_type (`json`, `text`, `form`),
session_ref, depends_on. The direct probes endpoint accepts the unchanged C2
AttackHypothesis plus Probe(hypothesis_id,op,binding,parent_probe_id,depth,motivation).
Canonical method/path comes from C1. Unknown/required parameters, body schema
violations and unresolved references block. C1 loses requestBody.required/media
type; C3 conservatively requires a body when a schema exists. HGS's heuristic
`alternate_tenant_id` is a hint, never a real ID. Provide explicit bindings.

Results include audit/hypothesis/probe/correlation IDs, operation, status, HTTP
code, sanitized headers, parsed metadata/body hash, latency, attempts, errors,
approval flag, risk classification, state changes and fingerprint. Arbitrary request/response text
and secret artifacts are omitted from user-facing evidence. Evidence hashes
and encrypted journal entries preserve provenance.
Binary responses currently preserve their hash and metadata rather than the full
binary payload. Text/JSON response contents are retained in the encrypted journal.

Interpretation output includes classification, confidence, evidence references,
observed/expected behavior, concise explanation, state changes, next action,
replan/approval flags and error. HTTP 200 alone is weak; 403 without violation
evidence is negative; 5xx halts as ERROR_CRASH. Timeout explanations explicitly
deny that they prove a crash. Confirmation requires a configured forbidden-value
predicate, protected-field presence and the expected auth context. Optional
expectation.owasp_categories restricts eligible hypotheses. Prior same-hypothesis
rejection evidence is referenced. Confidence is rule-based, not calibrated.

401 is authentication failure; 404 hides unknown/unowned audit/probe; 422 is
schema validation; 503 is upstream unavailable; 409 is a policy conflict.
Probe errors are structured results. Correlation IDs are preserved when valid,
otherwise generated. Upstream error strings are not exposed.

## Tools, sessions and privacy

`Tools(executor,audit,owner,hypothesis,probe,correlation)` binds identity and
operation outside LLM arguments. `definitions()` returns C2-style function
schemas; `await invoke(name,args)` validates before execution. http_request must
match the bound endpoint; parse_response references a real stored probe;
read_session_state returns redacted references; write_session_state permits
model-authored observations, never fabricated credentials/IDs.

The authenticated operator state API provisions approved tokens/cookies. Only
schema-declared response identifiers are extracted automatically. Credentials
need explicit operation.response_credentials paths, schema validation and token
syntax checks. They remain candidates, not proof of a successful login. Arbitrary
token-looking text is ignored. Approved credential_refs scope them to the same
audit and target origin. Bearer, common header API keys and explicit cookie strings
work; OAuth refresh, Basic and automatic cookie-jar harvesting are not implemented.

SQLite upserts are keyed by audit/category/key, preserving unrelated state.
BEGIN IMMEDIATE serializes budgets/dedup across instances. Fernet encrypts
contexts, evidence and state. Owners derive from configured API tokens, never
caller-supplied user headers. C4 trusts the machine token and checks audit owner;
restrict that token to service operators. Key rotation, retention/erasure automation
and multi-host network-share SQLite are not implemented.

## Mutation, budgets and recovery

Observed missing_header can select only configured permitted header values.
Observed invalid_parameter can select schema boundaries or enum/default body
values. Observed missing_parameter can reuse a previously observed ID. An explicit
compare_auth_context flag may select existing sessions listed in operation
auth_context_variations and target credential_refs. Each proposal carries the
parent observation, original hypothesis, change and depth. C3 revalidates ancestry,
schema, authorization, risk, dedup and budget before execution. Target text is data.

Duplicate fingerprints terminate no-progress execution. Probe/mutation/depth/model/
duration limits persist. Shared DB network slots cap concurrency and pace starts;
expired permits recover after process failure. A 5xx conservatively halts the whole
audit, avoiding repeated probes of an unstable service. Cancellation is checked
before sending/during streaming; an in-progress waiting read ends within timeout.

Reservations commit before sending. Unknown outcomes after restart are never
replayed automatically. An operator must review and start a fresh scoped audit
if appropriate. C4 failure permits reinterpreting stored evidence without replaying
the initial probe. Workflow checkpoints retain hypothesis/step/mutation progress.
Planner handoff pending/done markers prevent automatic retries after unknown
outcomes because C2 provides no idempotency contract. HGS queue/knowledge is
target-scoped; do not share one HGS target queue across independent concurrent
audits. No raw credentials are sent in planner handoffs.

## Optional model

`interpreter.gemini.GeminiProvider` uses ChatGoogleGenerativeAI with native JSON
schema output and typed Recommendation validation. `.env` loads without replacing
existing environment variables. GOOGLE_API_KEY takes precedence over GEMINI_API_KEY;
GEMINI_MODEL and PENAGENT_LLM_PROVIDER select the provider. Secrets are excluded
from prompts, public evidence and logs. LangSmith tracing is disabled for calls.
Timeouts, transient retries, output tokens and persistent per-audit LLM budgets
are bounded. The existing function-calling adapter remains available through
llm_url/model and PENAGENT_LLM_KEY. C2's planner is preserved.

The model receives numeric status, deterministic classification, boolean evidence
predicates and approved mutation choices. It receives no arbitrary target response
strings, credentials or free-text hypotheses. Recommendations select actual
validated candidates for header, parameter, body, auth-context and observed-state
strategies. The model cannot promote confirmation or authorize requests.
Malformed/unavailable output preserves evidence and stops model-assisted mutation.
Real Gemini native structured output and C1-C4 HTTP flow were verified with
gemini-3.1-flash-lite. Availability is key-specific; catalogue presence alone did
not guarantee generation (a different listed model returned 404). Use
`demo.gemini_check` before configuring a model. The offline path needs no key.

Docker reproduction from repository root after installation:

```powershell
python -B -m demo.prepare_docker
docker compose build
docker compose up -d --wait --wait-timeout 120
python -B -m demo.docker_verify --require-gemini --output reports/docker-gemini.json
docker compose restart executor interpreter
python -B -m demo.docker_verify --restart-check --output reports/docker-gemini.json
```

For an offline deployment leave PENAGENT_LLM_PROVIDER=none and omit
--require-gemini. Real provider checks consume the configured account's quota.
`demo.gemini_application` verifies ephemeral TCP services with Gemini;
`demo.juice_check --url <explicitly-authorized-origin>` is a supplementary read-only
C3/C4 root request, not a full Juice Shop benchmark or vulnerability discovery.
No benchmark inputs are generated by these commands.

## Verification and troubleshooting

```powershell
.\.venv\Scripts\python.exe -B -m pytest tests -q
.\.venv\Scripts\python.exe -B -m pytest tests/test_integration.py tests/test_recovery_and_limits.py -q
.\.venv\Scripts\python.exe -B -m demo.run --output reports/demo.json
.\.venv\Scripts\python.exe -B -m pytest c1-spec-ingestion/tests -q
.\.venv\Scripts\python.exe -B -m pytest c2-hypothesis-gen/tests -q
```

Historical suites must run separately because both use package `tests`. Their
missing benchmark inputs are recorded in AUDIT.md; do not fabricate replacements
to turn them green. The demo starts actual HTTP servers with ephemeral ports and
generated test-only credentials, then shuts them down. Its positive result is
simulated, not a claim about a benchmark or real target.

401: choose C3 principal/C4 machine token correctly. Invalid key: restore the
original Fernet key. Unauthorized destination: check exact reviewed scheme/IP/port.
Missing context: provide explicit bindings or observed references. 503: verify
trusted upstream URLs/health; target network errors are separate probe results.
Unknown outcome: inspect durable reservation, never blindly replay. Docker absent:
start the intended daemon and review target authorization before benchmark tests.
The source documentation does not fully specify benchmark reset procedures.
