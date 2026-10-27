# OWASP ZAP automated active-scanning baseline

**One approved root-only smoke scan completed and reports verified.** It finished
in 62.672 seconds, forwarding 3 requests and blocking 22. See
[the actual execution report](docs/SMOKE_RESULT.md). No additional scan or full
benchmark is authorized. The original failure and correction remain documented in
[the preflight record](docs/SMOKE_PREFLIGHT.md) and [deadline fix](docs/DEADLINE_FIX.md).

This independent baseline uses the official Docker packaged **API active scanner**
(`zap-api-scan.py`) or a separately labeled **full web active scanner**
(`zap-full-scan.py`). It never uses `zap-baseline.py` or the API scanner's `-S`
passive-only option. Components 1-4 are unchanged. Nothing is committed or pushed.

The completed smoke run does not establish API benchmark readiness. A planned manifest does not authorize a new scan. The
operator must explicitly approve the concrete scope/configuration before a run.
See the [audit](docs/AUDIT.md), [inventory](targets/inventory.json),
[data/metric contract](docs/DATA_CONTRACT.md) and [verification](docs/VERIFICATION.md).

## Prerequisites and Windows 11 setup

1. Open Docker Desktop and wait for its Linux engine to be running.
2. Open VS Code's PowerShell terminal in the PenAgent repository root.
3. Use Python 3.11+. This tooling uses only the standard library. If `python`
   resolves to an old or incomplete installation, use the exact executable shown
   in the verification record. No API keys are needed for anonymous tooling tests.
4. Keep projects, credentials, raw scan exports and results in ignored baseline
   `local/` or `results/`. Never put a real token/password in a command argument,
   tracked configuration, report committed to Git or shared screenshot.

```powershell
docker version
docker compose version
docker ps -a
docker images
python -B -m unittest discover -s baselines/zap/tests -v
```

Docker commands need normal access to Docker Desktop's named pipe. Codex's
sandbox may require an approval even for read-only inspection.

## Official scanner installation and pinning

If not already present, pull only the official image:

```powershell
docker pull ghcr.io/zaproxy/zaproxy:stable
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' ghcr.io/zaproxy/zaproxy:stable
```

The inspected installation is ZAP **2.17.0**, pinned to:

```powershell
$zapImage = 'ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6'
docker run --rm --network none $zapImage zap.sh -version
docker run --rm --network none $zapImage zap-api-scan.py -h
docker run --rm --network none $zapImage zap-full-scan.py -h
```

The runner intentionally rejects other images/versions until their flags, Python
API methods, installed rules and hooks are revalidated. `stable` is mutable;
an image pull is not an immutable experiment definition. No updates/add-on
downloads occur during timed scans: `-z '-silent'` disables automatic update
behavior in the inspected packaged scripts.

## Target startup and networking

The existing Juice Shop is `blissful_chebyshev`, version 20.0.0, host port 3000.
Always recheck its status; identifiers in the example manifest can become stale.

```powershell
docker inspect --format '{{.Id}} {{.Image}} {{json .State.Running}} {{json .NetworkSettings.Ports}}' blissful_chebyshev
docker image inspect --format '{{json .RepoDigests}}' bkimminich/juice-shop
docker exec blissful_chebyshev /nodejs/bin/node -p "require('/juice-shop/package.json').version"
```

If that identified container is stopped, `docker start blissful_chebyshev`
preserves its state. Do not delete, reset or replace it. Its existing all-interface
port binding was preserved. New experimental instances should publish loopback
ports only, use the same immutable image, and have fresh independent data. Do not
start new repeats or reset existing data without the separate experiment approval.

Verify a harmless root GET from the Windows host and scanner container:

```powershell
Invoke-WebRequest -Uri 'http://127.0.0.1:3000/' -TimeoutSec 5 | Select-Object StatusCode
docker run --rm --network bridge --entrypoint python $zapImage -c "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:3000/',timeout=5).status)"
```

Both returned 200 during this audit. Host `127.0.0.1` is not container loopback.
For Docker Desktop, `host.docker.internal:3000` reaches the published target.
Do not scan C1-C4 on 9001-9004 or the synthetic fixture on 9010.

The actual runner inserts a **scope gateway** between ZAP and Juice Shop. ZAP is
on a newly created internal Docker network; only the gateway has an upstream
bridge connection. There are no published ZAP API or gateway ports. Before ZAP
starts, the runner tests that direct connections to the host mapping and target
container IP are blocked. If the gateway can be bypassed, it refuses the scan.

The gateway forwards only reviewed HTTP method/path operations to the one pinned
target mapping, enforces single-request concurrency, pacing, request cap and
deadline, and records allowed/denied traffic. It does not follow redirects. It
removes external redirect destinations, fixes the upstream host, strips scanner
credentials/cookies and optionally supplies one reviewed fixed Bearer token.
Target responses are forwarded without introducing Python server fingerprints.
This changes transport/session behavior and restricts attack coverage: report
those limitations. Full browser/session/OAuth workflows are not implemented.

Safe routing verification (starts only the gateway, not ZAP scanning):

```powershell
python -B -m baselines.zap verify-network baselines/zap/config/juice-smoke.json --out baselines/zap/local/network-check-new
```

It uses Docker TCP readiness/routing tests, not active attacks. Each verification
directory must be new. Created gateway containers are stopped and retained for
inspection; no existing containers, data or networks are removed. Runtime scanner
and gateway containers are similarly retained after a run with labels
`penagent.zap-baseline=true`.

## Choose and freeze the experimental condition

`config/juice-smoke.json` is a concrete **anonymous full-web smoke condition**:

| Setting | Value |
|---|---|
| Target | Existing Juice Shop 20.0.0, pinned identity/digest |
| Forwarded operations | Exact `GET /` only; all other requests blocked |
| Active rule | 40018, in-band SQL injection, LOW strength / MEDIUM threshold |
| Other active rules | Disabled before enabling the explicit allowlist |
| Concurrency / spacing | 1 / minimum 250 ms |
| Request limit | 100 attempted upstream requests, gateway enforced |
| Total time | 180 seconds overall, including a 10-second shutdown reserve; new work stops by 170 seconds |
| Network timeout | 5 seconds |
| Traditional spider | Maximum 1 minute and depth 1 |
| Modern/AJAX spider | Disabled |
| Resources | ZAP 2048 MB/1 CPU; gateway 256 MB/0.5 CPU |

This is a **scope-control smoke test**, not representative API or whole-app
coverage. Root responses often provide no injection inputs, so the scan may
exercise little useful active logic. No API endpoints are guessed to improve it.
No destructive routes, state-changing verbs, external callbacks or OAST rules are
enabled. Every allowed operation, including GET semantics, needs review.

For a research API condition, obtain and review the real C1 specification and
version provenance first. Set `scan_mode=api`, fill OpenAPI paths/hashes, choose
the reviewed operation subset and freeze auth, rules, budgets, versions and resets.
Supported in-band active rule IDs are 40018 (SQL injection), 40012 (reflected XSS)
and 6 (path traversal); only enable those appropriate to the specific condition.
Filtering paths can prevent traversal checks from reaching the target: record
blocked attack attempts, not a claim of unrestricted scanner capability.

Review the installed effective rule list rather than assuming ZAP's defaults.
The configuration hooks disable all active rules and enable only the manifest
allowlist immediately before the packaged helper begins active scanning. ZAP is
put in protected mode with an explicit context; the gateway independently enforces
method/path restrictions. Any rejected required API action or mismatched effective
rule set aborts. No extra arbitrary `-z` options or unreviewed hooks are accepted.

## OpenAPI preparation: primary API baseline

There is currently **no valid target API definition** in this checkout. C1's live
Juice candidate returned HTML, so API-only readiness is blocked. See
[spec preparation limitations](specs/README.md). Do not treat an HTML response or
a synthetic fixture schema as the benchmark definition.

Once you obtain the exact C1 source, preserve it under `specs/original/`, perform
full OpenAPI validation and prove its deployed-version association. Create an
ignored JSON file containing reviewed operation strings, including the server
base path. The preparer checks structure and local refs, preserves API semantics,
filters only the reviewed operation subset and changes only the server origin.

```powershell
python -B -m baselines.zap prepare --source baselines/zap/specs/original/target.json --allowed-file baselines/zap/local/allowed-operations.json --out baselines/zap/specs/prepared/target.json
```

For a **real, verified** URL-based definition on the approved loopback target:

```powershell
python -B -m baselines.zap prepare --source 'http://127.0.0.1:18002/openapi.json' --host-origin 'http://127.0.0.1:18002' --allowed-file baselines/zap/local/allowed-operations.json --out baselines/zap/specs/prepared/target.json
```

The second example is conditional; SREBench is not currently deployed. URL input
is fetched without redirects, preserved unchanged and pinned locally before
scanner import. Record source URL, original/prepared hashes and the transformation
sidecar. Do not run it on an unverified service. Preflight regenerates the reviewed
transformation and rejects changed schemas or operations. API manifest `openapi`
must contain `source`, `source_sha256`, `prepared`, `prepared_sha256` and
`target_version_verified=true`. These flags assert actual review, not automatic proof.

## Authentication

Anonymous mode strips Authorization and Cookie on upstream requests, keeping a
consistent anonymous role. It cannot evaluate multi-step cookie session workflows.
For a separate fixed-Bearer condition, store only the token in an ignored local
file, set mode `fixed_bearer`, role and secret file reference in a private manifest,
and record a verified harmless authenticated request in `verification_ref`.
Preflight validates the secret file location; only the gateway gets a read-only
secret mount. The token is not put in command arguments or normalized reports.
Only a minimal runtime code bundle is mounted into the scanner, so it cannot
read the baseline's surrounding `local/` secrets directory.
Expired/unverified credentials block a fair authenticated evaluation. Dynamic
login, OAuth and arbitrary exported ZAP contexts are unsupported; configure and
validate a separate protocol before using them. Never mark auth verified solely
because a token string exists.

## Dry-run, explicit approval and first active scan

Inspect the manifest and exact intended scanner command without Docker or any
target traffic. Dry-run writes no files and never mutates the target:

```powershell
python -B -m baselines.zap validate baselines/zap/config/juice-smoke.json
python -B -m baselines.zap dry-run baselines/zap/config/juice-smoke.json --out baselines/zap/local/juice-smoke-r1
```

**Stop here until the operator explicitly approves the concrete active scan.**
This is required by the user's Phase 14 instruction, not an inferred approval
policy. The following commands are supplied for the operator after review; they
have **not** been executed here:

```powershell
python -B -m baselines.zap approve baselines/zap/config/juice-smoke.json --operator 'YOUR_OPERATOR_ID' --statement 'I approve one bounded active scan' --out baselines/zap/local/juice-smoke-approval.json
python -B -m baselines.zap run baselines/zap/config/juice-smoke.json --approval baselines/zap/local/juice-smoke-approval.json --out baselines/zap/local/juice-smoke-r1
```

The approval binds the exact manifest and implementation hashes and permits one
attempt. Edits invalidate approval. A `.used` marker prevents reuse; failed
preflight also consumes that approval. Use a new reviewed run/approval after fixing
the failure. It never authorizes the three-repeat experiment. Results directories
cannot already exist: runs never overwrite evidence. One monotonic deadline covers
preflight, setup, scanner execution, report collection and cleanup. Every new phase
checks the remaining allowance; expired timeouts are never rounded up. Ten seconds
inside the 180-second budget are reserved for shutdown, so new work and forwarding
stop no later than the 170-second work cutoff. The gateway starts disarmed and
uses a conservative cross-clock handshake to inherit the host's remaining time.
Permanent revocation closes forwarding before scanner cleanup; the gateway also
enforces its own monotonic expiry and closes any active upstream socket.

Cleanup verifies a per-run UUID label before force-stopping only that run's
gateway/scanner/diagnostic containers. It has no extra five-second grace outside
the total budget. A remaining-time check also follows DNS/connect before any HTTP
request is sent. OS scheduling, Docker-daemon stalls and unavoidable final local
evidence writes cannot be guaranteed as real-time operations: any observed overrun
or unconfirmed cleanup is recorded, never converted into permission for a new
phase. If the overall budget is already exhausted, no new Docker cleanup commands
are launched; the gateway remains disarmed/expired/revoked and unresolved resource
state is reported for inspection. No scan phase or retry is launched automatically.

Packaged exit codes are 0 (no WARN/FAIL), 1 (FAIL alerts), 2 (WARN alerts), 3 (tool
error). Codes 1/2 are not necessarily failed execution. Completion additionally
requires actual active scan IDs at 100%, the helper-return marker, report exports
and nonzero forwarded target traffic. A warning exit code alone never proves a
scan completed. The command exits 3 for failed/incomplete/timed-out orchestration.
`-T` is only startup/passive-wait timeout; the runner/gateway enforce total time.

## Reports, metrics and comparison

Actual run outputs go under the chosen ignored directory:

```text
manifest.json, approval.json, plan.json, command.json
run.json, isolation.json, scanner.log
zap.json, zap.html, zap.xml
hook-started.json, active-starting.json, active-finished.json
scanner-statistics.json, traffic.jsonl, gateway-summary.json
```

Raw files stay unchanged. The run record contains image/target/protocol metadata,
status, timestamps, duration, exit code and artifact hashes. Aborted runs may lack
reports: retain them as failed/partial records rather than manufacturing exports.
Inspect container logs for startup issues, keeping them private.

After a real approved run:

```powershell
python -B -m baselines.zap collect baselines/zap/local/juice-smoke-r1
```

This creates normalized findings, observations, metrics and derived hashes.
Coverage comes from actual gateway traffic, not imported paths or alert locations.
The separate CLI also accepts real packaged JSON or XML exports:

```powershell
python -B -m baselines.zap import-zap baselines/zap/local/juice-smoke-r1/zap.json --target juice_shop --out baselines/zap/results/zap.json
python -B -m baselines.zap import-zap baselines/zap/local/juice-smoke-r1/zap.xml --target juice_shop --out baselines/zap/results/zap-from-xml.json
```

Export C3 evidence and its C1 graph using the existing authenticated operator
workflow. Keep Bearer tokens out of shell history and tracked files:

```powershell
python -B -m baselines.zap import-penagent baselines/zap/local/penagent-evidence.json baselines/zap/local/graph.json --out baselines/zap/results/penagent.json
python -B -m baselines.zap metrics baselines/zap/results/zap.json baselines/zap/local/observations.json baselines/zap/config/juice-smoke.json --out baselines/zap/results/metrics.json
python -B -m baselines.zap compare baselines/zap/results/zap.json baselines/zap/results/penagent.json --out baselines/zap/results/comparison
```

`config/observations.template.json` shows the observation input. `metrics --truth
<verified-annotations.json>` enables detection metrics only with complete verified
version-specific truth and labels for every finding. Without those inputs,
TP/FP/FN/precision/recall/F1 and verified findings remain **N/A**. Gateway-denied
responses can generate scanner alerts: attribute evidence before judging them as
target findings. No alert automatically becomes a verified vulnerability.

Comparison creates JSON/CSV/Markdown and provenance hashes. Use optional
`--zap-annotations <file> --penagent-annotations <file>` for evidence-reviewed
taxonomy/template/defect identities, preserving both tools' original findings.
Unknown/ambiguous matches require review. See the data contract for formats.

## Three repeats and fairness

The proposal requires three independent runs per condition, with mean and sample
standard deviation. This smoke approval does not authorize that experiment.
After separate approval, use fresh equivalent target data, the same immutable
target version, auth role, logical operation set, time phases, budgets and frozen
rules. Do not run both tools concurrently on one mutable target. Record three
different reset/initial-state evidence references and retain unsuccessful runs.

```powershell
python -B -m baselines.zap aggregate baselines/zap/results/run1-metrics.json baselines/zap/results/run2-metrics.json baselines/zap/results/run3-metrics.json --out baselines/zap/results/aggregate.json
```

Aggregation rejects different mode/config fingerprints, failed/incomplete statuses,
duplicate repeats and missing/distinct reset records. Equal time does not imply
equal requests. Gateway overhead/session restrictions must either be applied
equivalently to PenAgent in a separately reviewed configuration or reported as a
confound. A root-only full-web smoke is not a fair substitute for a spec-guided API
benchmark. Do not pool API and web conditions. Missing/unsupported operations must
stay visible, not be removed after seeing results.

## Troubleshooting

- **Docker pipe access denied:** use a normal Docker-authorized terminal or approve
  read-only Docker access. Client version does not prove server availability.
- **Identity mismatch:** re-inspect the actual container, version, digest and ports;
  update a new reviewed manifest and obtain fresh approval. Never bypass preflight.
- **OpenAPI candidate returns HTML:** it is not a definition. Obtain the real C1
  asset; no fabricated API is created. Full-web fallback remains separate.
- **Gateway bypass test fails:** stop. Do not remove the check. Diagnose Docker
  internal networking or create a verified restricted network before scanning.
- **Many 403/502 responses:** inspect private gateway logs; blocked routes are
  scope exclusions, while 502 is a gateway/target transport problem. They do not
  automatically establish target vulnerabilities.
- **No injection inputs at root:** expected for this narrow smoke. Do not broaden
  to unknown endpoints automatically. Review a real API specification/operation set.
- **Hooks reject a method/rule:** installed version/add-ons differ. Revalidate the
  pinned image and effective settings offline. No fallback to an unrestricted scan.
- **Timeout/missing JSON:** retain partial logs/status. Do not make an empty report
  or count incomplete scans as successful repeats.
- **Expired Bearer:** stop and verify the auth role using a harmless allowed request;
  preserve new auth verification provenance without saving credentials in Git.

## Reproducibility checklist

- [ ] Target identity/version/digest and host/container connectivity verified.
- [ ] Source spec/version provenance validated, or fallback labeled full web.
- [ ] Every eligible method/path reviewed, with exclusions frozen before findings.
- [ ] Image version/help, configuration hooks, effective rules and network isolation verified.
- [ ] Authentication verified; secrets private; external/OAST rules disabled.
- [ ] Concrete manifest and implementation approved for one bounded active scan.
- [ ] Real active scan IDs, completion/status, counts, durations and raw exports retained.
- [ ] Gateway artifacts distinguished; actual coverage and independent adjudication recorded.
- [ ] Separate approval for three equivalent repeats and fair PenAgent comparison.
- [ ] All failed/interrupted records retained; missing truth-dependent metrics stay N/A.

Official references: [API scan](https://www.zaproxy.org/docs/docker/api-scan/),
[Full Scan](https://www.zaproxy.org/docs/docker/full-scan/),
[scan hooks](https://www.zaproxy.org/docs/docker/scan-hooks/) and
[Docker images](https://www.zaproxy.org/docs/docker/about/).
