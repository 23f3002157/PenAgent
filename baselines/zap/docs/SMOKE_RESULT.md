# Single approved ZAP smoke execution - 2026-10-25

**Status: IMPLEMENTED AND SCAN VERIFIED, for the root-only full-web smoke condition.**
Exactly one real packaged scan ran. No retry, second scan or three-repeat benchmark
was launched. This is not an API-level research benchmark or evidence of scanner
recall/precision. The original approved configuration remains unchanged.

## Actual outcome

| Observation | Recorded value |
|---|---|
| Target | Existing `blissful_chebyshev`, OWASP Juice Shop 20.0.0 |
| Scan mode | `zap-full-scan.py`, restricted root-only full-web smoke |
| Run ID | `1e3d015cb9ea4bdebd16fdab8bc4f1ae` |
| Start / end | 2026-10-25 21:40:14 / 21:41:16 IST |
| Measured total monotonic duration | **62.672 seconds**, including orchestration and cleanup |
| Overall limit / cleanup reserve | 180 seconds / 10 seconds within that budget |
| Timeout / overrun | No / 0 seconds |
| Forwarded target requests | **3**, all `GET /`, HTTP 200 |
| Blocked gateway requests | **22** |
| Forwarded-request maximum | 100; not reached |
| Effective enabled active rules | **40018 only**, LOW attack strength, MEDIUM alert threshold |
| ZAP mode | Protected (`protect`) |
| Active task | ID 0, FINISHED, progress 100%, scanner request count 6 |
| Active task alerts | **0** |
| Packaged exit code | **2**, WARN alerts; not execution failure |
| Actual report import | JSON and XML succeeded; normalized finding IDs match |
| HTML | Generated and parsed with the standard HTML parser |
| Final cleanup | Run gateway killed; scanner already stopped; diagnostics auto-removed |
| Forwarding permission | Permanently revoked before cleanup |

The active task's six requests are ZAP's task counter, not a claim that six reached
Juice Shop. The gateway recorded only three attempted upstream HTTP requests.
Discovery, active requests, denials and forwarding have different counter meanings.
Full traffic evidence independently reconciles the 3/22 gateway totals.

## Alerts by severity

| Severity | Raw alert types | Normalized records |
|---|---:|---:|
| High | 0 | 0 |
| Medium | 2 | 6 |
| Low | 2 | 6 |
| Informational | 1 | 1 |
| Total | **5** | **13** |

All 13 records were identified as passive-rule observations using the actual
installed rule inventory. Raw types were CSP Header Not Set (10038), Cross-Domain
Misconfiguration (10098), Server Leaks Version Information (10036), Timestamp
Disclosure (10096) and Modern Web Application (10109, informational).

These are scanner observations, not 13 independently verified vulnerabilities.
Several instances concern gateway-generated HTTP 403 responses for excluded
resources. In particular, the server-header warning includes the gateway's denial
responses and must not be attributed wholesale to Juice Shop. Preserve raw alerts
and adjudicate their origin rather than deleting them or treating them as verified
target findings. The console's four WARN types exclude the informational type;
the machine-readable reports contain five types. Its printed PASS inventory also
does not prove that disabled active checks ran. The recorded effective active
allowlist contains only 40018.

## Preconditions and actual validation

- Approved manifest, corrected implementation and unchanged policy hashes matched.
- Full container ID, image ID/digest and published port were rechecked inside the
  run before scanner launch, and target identity/running state checked afterward.
- The dedicated internal scanner network passed direct-target bypass tests before
  launch. No ZAP control port was published; only the gateway could reach the
  verified target mapping. No PenAgent service or external target was scanned.
- **72 regression tests passed in 2.496 seconds** before this scan. The replayed
  181-second setup scenario launched no scanner; the updated gateway accepted
  exactly 100 mocked requests and denied request 101. Those test counts are
  separate from the real scan's 3 forwarded / 22 blocked requests.
- JSON/XML import each produced 13 normalized records with identical IDs. Raw
  JSON/XML/HTML, original manifest, scanner log and traffic hashes still matched
  the final runner record after processing. No raw report was changed.
- No application execution error was found. Exit 2 denotes warnings. Cleanup's
  `no such object` diagnostic messages refer to disposable probes that already
  removed themselves; they are not scan failures. Gateway exit 137 reflects its
  deliberate force-stop after forwarding revocation.

## Generated evidence

All private outputs are under ignored `baselines/zap/local/juice-smoke-r1/`:

| File | Purpose |
|---|---|
| `zap.json`, `zap.xml`, `zap.html` | Actual unchanged ZAP reports |
| `scanner.log` | Actual packaged scanner output |
| `manifest.json`, `approval.json`, `plan.json` | Approved inputs and bound approval |
| `command.json` | Exact Docker scanner argument array |
| `run.json` | Final run manifest, monotonic duration, status, cleanup and raw hashes |
| `traffic.jsonl`, `gateway-summary.json` | Forwarded/denied requests and operation coverage |
| `isolation.json` | Actual pre-launch network checks |
| `active-starting.json`, `active-finished.json`, `scanner-statistics.json` | Effective rules and active execution evidence |
| `normalized.json`, `normalized-from-xml.json` | Actual imported report records |
| `observations.json`, `metrics.json`, `derived-hashes.json` | Supported metrics and derived provenance |
| `execution-summary.json`, `verify_actual.py` | Reconciled verification summary and read-only verifier |

The one-use approval is
`local/smoke-user-approval-20261025-corrected-once.json` with its consumed `.used`
marker. Permanent forwarding revocation is recorded under
`local/runtime-control/1e3d015cb9ea4bdebd16fdab8bc4f1ae/forwarding.closed`.
No additional scan is authorized by keeping these artifacts.

## Exact commands executed

From the repository root in PowerShell; these are the historical commands for
this single run. The consumed approval and existing output directory prevent reuse.

```powershell
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s baselines/zap/tests -q
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B baselines/zap/local/deadline-fix/replay_constraints.py
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m baselines.zap approve baselines/zap/config/juice-smoke.json --operator user-explicit-chat-approval-2026-10-25 --statement 'I approve one bounded active scan' --out baselines/zap/local/smoke-user-approval-20261025-corrected-once.json
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m baselines.zap run baselines/zap/config/juice-smoke.json --approval baselines/zap/local/smoke-user-approval-20261025-corrected-once.json --out baselines/zap/local/juice-smoke-r1
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m baselines.zap collect baselines/zap/local/juice-smoke-r1
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m baselines.zap import-zap baselines/zap/local/juice-smoke-r1/zap.xml --target juice_shop --out baselines/zap/local/juice-smoke-r1/normalized-from-xml.json
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B baselines/zap/local/juice-smoke-r1/verify_actual.py
```

The exact generated Docker command, including image digest, run labels, network,
read-only code mount, report flags and hook path, is retained in `command.json`.
No scanner implementation, policy, approved configuration or PenAgent component
was changed during this execution. Existing target state was not reset. Nothing
was committed or pushed.

## Remaining work for the full API benchmark

1. Obtain authoritative OpenAPI source bytes matching the deployed target version
   and the actual C1 input. The documented candidate still lacks a usable spec.
2. Review a broader eligible operation set and exclusions, and validate matching
   authenticated roles and initial data for PenAgent and ZAP. Root-only coverage
   of one eligible operation is not whole-application coverage.
3. Deploy and verify DVWS/SREBench if including them; do not infer their availability
   from documentation or invent benchmark assets.
4. Obtain version-specific eligible ground truth and independent adjudication,
   including gateway-response attribution. TP/FP/FN, precision/recall/F1 and
   verified-findings metrics remain N/A.
5. Establish equivalent fresh-state/reset records, comparable traffic accounting
   and transport conditions, then seek separate approval for three independent
   repeats per condition. No benchmark repeat was run under this smoke approval.
