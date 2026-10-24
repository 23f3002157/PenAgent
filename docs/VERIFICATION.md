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
| Components 5/6 and full LangGraph | OUT OF SCOPE | default-deny gate and durable minimal orchestration interfaces |

No real-world vulnerability discovery, calibrated confidence, full human approval
UI, multi-host SQLite deployment or automatic replay of uncertain requests is
claimed. All five mutation strategies have independent tests; model failure
branches use test doubles in addition to separate real-provider verification.
