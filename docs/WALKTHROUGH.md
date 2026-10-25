# Running PenAgent and watching what it does

A step-by-step operator walkthrough: start the system, point it at a target,
drive an audit, and read what it decided at every step. For install options,
the full API reference and configuration fields, see [EXECUTION.md](EXECUTION.md).
This walkthrough uses the Docker Compose path because it is the fastest way to
get all six components running; the same HTTP calls work identically against
the native `uvicorn` processes described in EXECUTION.md.

Every example below is real output from this repository's own verification run
(`docs/VERIFICATION.md`, 2026-10-25), not placeholder text.

## 1. Start everything

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -B -m demo.prepare_docker
docker compose build
docker compose up -d --wait --wait-timeout 120
```

This brings up six containers: `sis` (C1, :9001), `hgs` (C2, :9002), `executor`
(C3 + Component 5, :9003), `interpreter` (C4, :9004), `report` (C6, :9005), and
`fixture` (a synthetic, isolated target for safe experimentation -- not
published to a host port). `demo.prepare_docker` also authorizes this fixture
as the only target in `runtime/docker.json`, generates your operator token, and
writes everything to the ignored `.env` file.

Get the credentials you'll use below:

```powershell
Get-Content .env | Select-String "PENAGENT_API_TOKENS|PENAGENT_SERVICE_TOKEN"
```

`PENAGENT_API_TOKENS` is a JSON map of `{"operator_name": "token"}` -- that
token is the Bearer credential for every call below (it's the *human operator*
identity). `PENAGENT_SERVICE_TOKEN` is the separate machine-to-machine
credential C4's internal routes require; you won't need it directly unless
you're calling `/interpret`/`/mutations` yourself instead of letting `/run`
do it.

## 2. Create an audit

```powershell
curl -X POST http://127.0.0.1:9003/v1/audits `
  -H "Authorization: Bearer <your-operator-token>" -H "Content-Type: application/json" `
  -d '{"audit_id":"demo-1","target_id":"fixture","acknowledged_authorization":true}'
```

`acknowledged_authorization: true` is a deliberate speed bump: you are stating
you're authorized to probe this target. `target_id` must already exist in the
loaded config's `targets` map (`fixture` always does, out of the box).

## 3. Let C1 ingest the spec and C2 generate hypotheses

```powershell
curl -X POST http://127.0.0.1:9001/v1/ingest -H "Content-Type: application/json" `
  -d '{"target_id":"fixture","base_url":"<fixture-base-url>","spec_source":"<fixture-base-url>/openapi.json"}'
# poll GET /v1/ingest/{job_id} until status is "done", then:
curl -X POST http://127.0.0.1:9002/v1/hypotheses/generate -H "Content-Type: application/json" `
  -d '{"target_id":"fixture","max_hypotheses":20}'
```

C1 parses the spec into an endpoint graph; C2 turns that graph into a ranked,
target-scoped queue of attack hypotheses. (C1/C2 are unauthenticated on the
trusted local network, by design -- see EXECUTION.md.)

## 4. Drive execution and watch it decide, one call at a time

```powershell
curl -X POST http://127.0.0.1:9003/v1/audits/demo-1/run `
  -H "Authorization: Bearer <your-operator-token>" -H "Content-Type: application/json" -d '{"bindings":{"1":{}}}'
```

Call this repeatedly (once per hypothesis/mutation round) until you see
`"status":"queue_empty"`. Each call's `status` field *is* the agent's decision
for that step -- this is the primary thing to watch:

| `status` | What it means |
|---|---|
| `hypothesis_finished` | This hypothesis is done (negative, or planner replan/next-hypothesis signal sent); call `/run` again for the next one. |
| `chain_halted` | A probe returned 5xx or crashed; classified `ERROR_CRASH`, not proof of a vulnerability, and this specific hypothesis stops here. |
| `duplicate` | An identical probe was already reserved; no progress, move on. |
| `queue_empty` | C2's queue for this target is drained; the audit is done for now. |
| **`awaiting_approval`** | **Component 5 paused.** A non-safe action (destructive op, `DELETE`, a dangerous-looking path, or a risky payload field) needs a human decision before it runs. See step 5. |
| `blocked` | Something was rejected outright (budget exhausted, cancelled, schema violation, etc.) -- check `error` for the reason code. |

Real example from this session, two consecutive calls on the same audit:

```json
{"status": "hypothesis_finished"}
{"status": "awaiting_approval", "error": "approval_required", "probe_id": "a91c4a0f669a43ee8e2dad0baad5b357"}
```

## 5. If it pauses for approval (Component 5)

```powershell
curl http://127.0.0.1:9003/v1/audits/demo-1/approvals -H "Authorization: Bearer <your-operator-token>"
```

Returns the pending request with a human-readable description: the method,
path, OWASP category, risk classification, the hypothesis's motivation, and
(if it's a mutation) the parent probe's reasoning. Decide:

```powershell
curl -X POST http://127.0.0.1:9003/v1/audits/demo-1/approvals/<probe_id> `
  -H "Authorization: Bearer <your-operator-token>" -H "Content-Type: application/json" `
  -d '{"decision":"approve"}'   # or {"decision":"deny","reason":"..."}
```

Approving replays *exactly* the stored request -- nothing about it can change
at decision time, and the bypass never applies to any other probe. Denying
blocks it permanently. Leaving it alone for `approval_timeout` (default 1800s)
auto-skips it. Either way, call `/run` again afterward to continue the audit;
PenAgent does not auto-resume a chain after an approval decision -- that next
step is yours.

## 6. Watch the evidence as it accumulates

```powershell
curl http://127.0.0.1:9003/v1/audits/demo-1/evidence -H "Authorization: Bearer <your-operator-token>"
```

This is the full redacted trace: every probe's `result` (status code, parsed
body *hash* -- never raw response text or credentials) and `interpretation`
(classification, confidence, plain-English `reasoning_summary`, `next_action`).
Real example, three probes from one hypothesis chain in this session:

```text
3704487b... -> STRONG_SIGNAL      | mutate         | "Response includes fields relevant to the hypothesis and conflicts with expected rejection..."
01375145... -> CONFIRMED_VULNERABILITY | replan    | "Configured forbidden object/context values and protected fields were observed..."
a91c4a0f... -> NEGATIVE           | next_hypothesis | "The request was rejected or the resource was absent, without evidence of a security violation."
```

It also returns the audit's `transitions` -- the literal state-machine history,
e.g. for that same audit:

```text
PLANNING -> INTERPRETING -> MUTATING -> INTERPRETING -> REPLANNING -> PLANNING -> AWAITING_APPROVAL -> INTERPRETING
```

That's a complete, honest trace of the agent's path: it tried a probe, got a
signal, mutated, confirmed, handed off to the planner, picked a new
hypothesis, hit a non-safe action, and paused.

## 7. Check what it has learned so far

```powershell
curl http://127.0.0.1:9003/v1/audits/demo-1/state -H "Authorization: Bearer <your-operator-token>"
```

Session knowledge gathered across probes -- tokens, cookies, discovered object
IDs, free-text observations -- redacted unless you hold the owning operator
token.

## 8. Pull the report (Component 6)

```powershell
curl http://127.0.0.1:9005/v1/audits/demo-1/report -H "Authorization: Bearer <your-operator-token>"
```

Callable at any point, reflecting whatever evidence exists so far. Real
example from this session (one finding, trimmed):

```json
{
  "audit_id": "docker-520fe12e36", "target_id": "fixture", "probes_executed": 3,
  "findings": [{
    "finding_id": "8ac0b635340e3b89",
    "title": "API5:BFLA on GET /admin/object",
    "classification": "STRONG_SIGNAL", "confidence": 0.75,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "cvss_score": 5.3, "severity": "medium",
    "probe_chain": ["3704487b96b84b76959d3cb81cfdc661"],
    "request_summary": ["...redacted per-step evidence, same shape as /evidence..."],
    "explanation": "...the probe's reasoning_summary + observed/expected behavior, concatenated...",
    "remediation": "Enforce function-level authorization checks server-side for every administrative or privileged operation..."
  }],
  "observations": [], "operational_issues": [], "summary": {"STRONG_SIGNAL": 1}
}
```

`findings` holds `CONFIRMED_VULNERABILITY`/`STRONG_SIGNAL` (CVSS-scored,
deterministic -- never LLM-assigned); `observations` holds `WEAK_SIGNAL`
(unscored); `operational_issues` holds `ERROR_CRASH` (a potential logic/DoS
bug, never scored as a vulnerability); `NEGATIVE` only affects `summary`
counts.

## 9. Clean up

```powershell
docker compose down          # stops the local stack (state in runtime/ survives)
docker rm -f penagent-testbed  # if you also started the real benchmark image
```

## Quick reference: what each classification means

| `classification` | Meaning | Where it shows up in the report |
|---|---|---|
| `CONFIRMED_VULNERABILITY` | Operator-configured forbidden value/context observed in the right auth state | scored finding |
| `STRONG_SIGNAL` | Relevant fields present, conflicts with expected rejection, not yet confirmed | scored finding |
| `WEAK_SIGNAL` | Unusual but not clearly exploitable | observation |
| `NEGATIVE` | Cleanly rejected, no useful evidence | summary count only |
| `ERROR_CRASH` | 5xx or transport failure; potential logic/availability bug, not proof of a flaw | operational issue |

## Running against a real target instead of the fixture

Edit `runtime/docker.json`'s `targets` map to add your authorized target (see
the `config.example.json` snippet in EXECUTION.md's "Configuration" section
for the shape -- `base_url`, `operations` with `method`/`path`/`risk`/
`expectation`), then `docker compose restart executor interpreter report` to
pick it up. `demo/testenv_verify.py` is a complete worked example of this
pattern against the real `monisha117/penagent-target-env` benchmark image
(Juice Shop, SREBench-API, DVWS) -- read it alongside this walkthrough if
you're pointing PenAgent at a new target for the first time.
