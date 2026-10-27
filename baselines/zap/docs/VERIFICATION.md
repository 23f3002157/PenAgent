# Executed verification - 2026-10-25

Latest result: **one real root-only full-web active smoke scan completed**, with
JSON/XML/HTML exports preserved and imports verified. Duration 62.672 seconds;
3 requests forwarded and 22 blocked; active task FINISHED at 100%, zero active
alerts. All reported observations were passive-rule records, including gateway
denial-response artifacts. See [the actual smoke execution report](SMOKE_RESULT.md)
for exact commands, counters, severity totals and remaining benchmark limitations.
The implementation and preflight verification statements below are historical.

Latest correction: the deadline defect found in the approved-smoke preflight is
fixed. **72 tests passed**, the previously failing 181-second setup now launches
nothing, and a TCP-only Docker isolation check passed without scanning. See
[the deadline fix record](DEADLINE_FIX.md) for exact commands, results and changed
files. The earlier 51-test result below is historical. No real active scan has run;
waiting for new operator approval.

Final status: **IMPLEMENTED, AWAITING SCAN APPROVAL** for the narrow full-web
scope-control smoke condition. API benchmark execution remains blocked by missing
authoritative specifications and ground truth. **No real active scan ran.**

Base commit: `fa6f8872622d60844027d3693572af44daf1c310`.
Runtime: Codex bundled Python 3.12.14, Windows 11. Final test command:

```powershell
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest discover -s baselines/zap/tests -v
```

**51 tests passed in 1.244 seconds** outside the sandbox. The initial 47-test
suite also passed inside the sandbox. After adding a real localhost guard test
with mocked upstream, the sandbox blocked its client socket with WinError 10013;
that attempt was not counted as a pass. The approved outside-sandbox rerun passed
all 51 cases. No test contacted Juice Shop or launched a real ZAP active scan.
Synthetic test approvals/reports/truth existed only in temporary test directories.

Coverage includes strict manifest/target/scope rejection, active-only command
construction, offline non-mutating dry-run, stale/one-use approval, unknown identity,
method/path allowlisting, real guard HTTP handling with mocked upstream, hard
forwarding cap, auth/query non-propagation into logs, minimal code mounts, OpenAPI
base-path preservation and filtering, refs/overrides/unknown operations, JSON/XML
parsing and blocked entities, malformed/missing/empty exports, alert deduplication,
missing severity/confidence, actual C3 audit target/graph shapes, signal exclusion,
CWE mapping, tentative/reviewed matching, immutable annotation views, missing truth,
precision/recall/F1, zero denominators, observed-only coverage, timeout cleanup,
incomplete status, three-repeat equivalence/stratification and comparison outputs.

## Actual installed scanner validation (not an experiment)

- Official pinned image present; no download needed. Version/help commands read
  from it, reporting ZAP 2.17.0 and supported API/full scan/report flags.
- First offline hook validation found incorrect policy-level setter arguments.
  The implementation was corrected to per-scanner strength/threshold setters.
- Corrected hooks were validated against an actual ZAP daemon **with Docker
  networking disabled**. Context creation/protected mode, concurrency, delay,
  timeout, active rule allowlisting/strength/threshold and final statistics capture
  all succeeded. Only configuration hooks were invoked, never the scan helper.
- Actual final daemon state: `active_scans=[]`, `discovered_urls=[]`,
  `message_count="0"`. Effective rule inventory captured. This is configuration
  evidence, not a successful active scan or a target findings report.
- Local private records:
  `baselines/zap/local/hook-validation/validation.json`,
  `active-starting.json`, `scanner-statistics.json` and `daemon.log`.
  An `active-starting.json` created by the offline configuration hook alone is not
  execution evidence; actual completion additionally requires recorded scan IDs.

## Actual connectivity and isolation validation

- Host `http://127.0.0.1:3000/`: HTTP 200 HTML.
- Scanner image bridge GET `http://host.docker.internal:3000/`: HTTP 200 HTML.
- Documented OpenAPI candidate: HTTP 200 **HTML**, rejected as a specification.
- Dedicated internal scanner network blocked direct TCP access to
  `host.docker.internal:3000` and the actual target container IP `172.17.0.2:3000`.
  Gateway TCP readiness succeeded; no ZAP scanner was launched.
- The final minimal runtime bundle was separately verified with the same routing
  checks. Evidence: `local/network-validation-bundled/isolation.json` and
  `gateway-summary.json`; zero forwarded requests in this verification.
- Newly created gateway containers were stopped. Existing Juice Shop, C1-C4 and
  fixture containers were not reset, replaced or deleted. Verification networks
  and stopped gateways remain labeled for inspection; no scan API was published.

Dry-run executed successfully, showing exact target identity, reviewed GET `/`
scope, active SQL-injection rule, budget, isolation settings and command arguments.
The final review record is stored locally as `local/final-dry-run.json`. No approval
artifact was created for a real run, and the run command was not invoked.

Manifest validation, Python/JSON syntax and Git ignore checks were performed.
`git diff --check` passed. Raw outputs/results are ignored. Only new files under
`baselines/zap/` were added; C1-C4 and all existing tracked files are unchanged.
No commit or push was performed. Actual ZAP target JSON/XML import and end-to-end
scanner completion can only be verified after the explicitly approved smoke run.

## Remaining work

1. Operator reviews and explicitly approves one bounded root-only full-web smoke.
2. Execute it, preserve real report/log/status evidence, run `collect`, and inspect
   gateway interference and actual active scan progression.
3. Obtain exact C1/deployed-version API definitions and eligible ground truth.
4. Establish equivalent fresh target state and authentication, then separately
   approve the full three-repeat experiments. No full experiment is implied by
   the smoke approval.
