# Overall deadline correction and verification - 2026-10-25

**Fixed and verified. No real active scan was executed. Awaiting operator approval.**

## Exact defect

The old runner waited with `max(1, wall_seconds - elapsed)` after launching the
scanner. An expired setup allowance therefore still launched a process and gave
it one extra second. Preflight was outside the timer, setup Docker calls each had
their own timeout, cleanup added independent grace periods, and the gateway
started a fresh 180-second timer when its process started.

## Correction

One host monotonic deadline starts at run entry and includes preflight, staging,
Docker setup, gateway startup, scanner execution, report generation/collection and
cleanup. The approved manifest is unchanged: the overall budget remains 180 seconds.
Ten seconds **inside** that budget are reserved for shutdown, leaving at most
170 seconds for new work. A phase checks time before launch. Docker commands and
scanner waits receive only the remaining positive allowance, capped by their
operation timeout. Expired allowances raise `DeadlineExpired`; they are never
rounded up to one second. Report hashing checks the same cutoff between chunks.

The gateway starts disarmed. It publishes a nonce and a sample of its own
monotonic clock in a private control directory outside the scanner mount. The
host adds its remaining work allowance to that older gateway sample, producing
a conservative gateway deadline even though Windows and the Linux container
have different monotonic epochs. This can expire early by handshake latency;
it cannot grant an additional fresh 180 seconds. An expired, missing, stale or
invalid allowance never authorizes forwarding. The gateway caches the deadline
once and cannot extend it through later control-file writes.

The runner's independent watchdog writes a permanent close marker at the work
cutoff, even if the main orchestration thread stalls. Normal completion, failure,
cancellation and timeout also revoke forwarding **before** Docker cleanup.
Gateway expiry/revocation seals admission permanently and closes its active
upstream socket. Remaining time is checked again after DNS/connect and before
starting any HTTP request. Body/connect/read timeouts are capped by that allowance.
Thus scanner shutdown cannot extend forwarding permission. The method/path
allowlist, anonymous credential filtering, request cap and scan policy are unchanged.

Only containers registered by the current invocation and carrying its exact
per-run UUID label may be force-stopped. Gateway shutdown precedes scanner
shutdown. Diagnostic containers are named and tracked too; their normal `--rm`
removal is recognized. Existing Juice Shop and PenAgent containers are never
cleanup candidates. The local Docker client can be killed/reaped only if this
invocation created it. Cleanup shares the original deadline, not an extra grace
period. If even the overall budget is exhausted, no new Docker subprocess is
started: unresolved cleanup is recorded while the gateway stays revoked/expired.

This is an application deadline, not a real-time OS guarantee. Process creation,
Docker-daemon stalls, kernel scheduling and essential final local evidence writes
may be non-preemptible. Observed overruns and unconfirmed cleanup are explicitly
recorded; they do not authorize another phase, retry or successful completion.

## Exact verification commands and actual results

All commands ran from the repository root with bundled Python 3.12.14:

```powershell
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s baselines/zap/tests -v
```

Final result: **72 tests passed in 5.629 seconds**. This includes all 51 existing
cases and 21 deterministic deadline regressions. The old cleanup test was adapted
to assert UUID-verified immediate shutdown instead of the removed five-second
grace; its temporary control directory is isolated per test. All clock/Docker/ZAP
execution in deadline regressions is mocked. The localhost HTTP guard fixture
uses a mocked upstream. Windows blocks that socket inside the sandbox, so the
complete suite ran with approved outside-sandbox execution.

Boundary coverage includes 181-second setup, exactly 180 seconds, exactly the
170-second work cutoff, a 0.25-second remaining allowance, preflight/setup overrun,
active-work timeout, revocation before gateway/scanner shutdown, cleanup constrained
to overall remaining time, ownership mismatch, already removed diagnostics,
report collection cutoff, wall-clock independence, watchdog revocation,
cross-clock handshake, unarmed/stale controls, expiry after connect and permanent
revocation/deadline non-extension.

The previously failed preflight script was replayed without overwriting its
original evidence. Only its test-bundle path and mock signature were adapted to
the corrected code; setup still advances the mocked clock to **181 seconds**:

```powershell
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B baselines/zap/local/deadline-fix/replay_constraints.py
```

Result: **PRECHECKS_PASS**. Scanner launches `[]`; scanner wait timeouts `[]`;
real target requests **0**. The updated gateway accepted exactly 100 mocked GET
`/` requests, blocked the 101st, and rejected all five disallowed method/URL
cases. Evidence: `local/deadline-fix/constraint-verification.json`.

A real Docker **TCP-only** validation, with no ZAP scanner or HTTP target request:

```powershell
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m baselines.zap verify-network baselines/zap/config/juice-smoke.json --out baselines/zap/local/deadline-fix/network-verification
```

Result: **isolation verified**. Target identity/image-digest preflight passed.
The new gateway/control mount started, the host deadline allowance was published,
TCP readiness passed and the scanner network could not directly reach
`host.docker.internal:3000` or `172.17.0.2:3000`. The only created gateway was
force-stopped after verifying its UUID label. Its gateway summary recorded zero
forwarded and denied HTTP requests; auto-removed diagnostic containers were absent.
Network/cleanup evidence is retained under that verification directory. The gateway
summary is an initial idle snapshot; independent expiry/clock-edge behavior is
verified by deterministic tests rather than asserted from an idle traffic log.

## Preserved invariants

Byte-hash comparison to the pre-edit snapshot confirms:

- `config/juice-smoke.json` is byte-identical: same 180 seconds, 100 requests,
  `GET /` operation set, target ID/image digest and rule 40018 LOW/MEDIUM policy.
- `hooks.py` and `common.py` are byte-identical, preserving policy and scope/target
  validation rules. Internal scanner network and fixed upstream mapping remain.
- All Component 1-4 and shared PenAgent Python source hashes are unchanged.
- The old approved generated bundle and original failed preflight artifacts are
  preserved. A separate updated runtime bundle was generated for verification.
- No existing target/container was reset, replaced or deleted. No scan, commit
  or push was performed. Updated implementation hashes invalidate old approval
  artifacts; the latest user instruction requires waiting for a new scan approval.

## Files changed by this correction

New:

- `deadline.py`: monotonic budget, reserve, permanent revocation and watchdog.
- `tests/test_deadline.py`: 21 deterministic regression cases.
- `docs/DEADLINE_FIX.md`: this verification and change record.

Updated:

- `runner.py`: shared phase budget, disarmed-gateway handshake, bounded report
  collection and ownership-checked cleanup.
- `gateway.py`: inherited expiry, revocation, capped I/O and post-connect check.
- `__main__.py`: safe verification command uses the same deadline/cleanup path.
- `tests/test_baseline.py`: existing cleanup regression adapted to the new contract.
- `README.md`, `docs/VERIFICATION.md`, `docs/status.json`: current behavior/status.

Ignored local evidence: `local/deadline-fix/before.json`, `invariants.json`,
`constraint-verification.json`, `replay_constraints.py`, `verification-runtime/`,
`network-verification/`, and the final review/dry-run record. Original failure
evidence remains under `local/approved-smoke-preflight/`.
