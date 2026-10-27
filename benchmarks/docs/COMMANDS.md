# Phase 4 command and output record

Run PowerShell from `C:\Users\Kushi KKS\PenAgentGenAi\PenAgent`.
The actual Python used was the bundled Python 3.12.14:

```powershell
$phase4Python = 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$phase4Repo = 'C:\Users\Kushi KKS\PenAgentGenAi\PenAgent'
$phase4Bench = Join-Path $phase4Repo 'benchmarks'
$phase4Zap = 'ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6'
git status --short
```

Initial output: `?? baselines/`. Final status additionally includes `?? benchmarks/`.
No commit, push, reset, clean, existing-container deletion or active scan command ran.

## Source and dependency capture

The read-only collection scripts used during the audit are retained under ignored
`benchmarks/local/`: `capture_sources.py`, `collect_remote.py`. Review them before
reuse; they refuse existing evidence and are not meant to overwrite this bundle.

```powershell
& $phase4Python -B benchmarks/local/capture_sources.py
& $phase4Python -B benchmarks/local/collect_remote.py
& $phase4Python -m pip install --target benchmarks/local/validation-deps openapi-spec-validator==0.7.2 PyYAML==6.0.3
& $phase4Python -B -m benchmarks.generate_specs
```

The first collector records preservation hashes, performs read-only `docker cp`
for source files, and GETs GitHub repository/commit/tag/release metadata. The second
GETs pinned recursive trees and selected source/deployment/spec files without
executing downloaded code. Source/tag byte comparisons succeeded. The initial
sandboxed dependency install had a DNS/network failure; the authorized network
retry succeeded. Generation output: official B2B origin copies and a labeled
five-operation derived subset; both full OpenAPI validations passed.

GitHub metadata endpoints used for each of `juice-shop/juice-shop`,
`snoopysecurity/dvws`, `snoopysecurity/dvws-node`:
`https://api.github.com/repos/{repo}`, `/commits?per_page=1`, `/tags?per_page=5`,
`/releases?per_page=5`. Tree URLs include the recorded commit and `?recursive=1`.
Raw source URLs use `https://raw.githubusercontent.com/{repo}/{commit}/{path}`;
Juice Shop selected file comparisons use tag `v20.0.0`.

## New isolated target creation (already performed once)

```powershell
docker compose -f benchmarks/deploy/juice-shop.compose.yml config --quiet
docker compose -f benchmarks/deploy/juice-shop.compose.yml up -d --pull never
docker inspect --format '{{.State.Running}} {{.State.ExitCode}} {{json .HostConfig.PortBindings}} {{json .NetworkSettings.Ports}}' penagent-phase4-juice20-r1-target-1
docker network inspect --format '{{json .Internal}}' penagent-phase4-juice20-r1_isolated
```

Compose validation passed; the distinct target/network were created without pulling
an image. Inspect: running `true`, exit `0`, requested loopback mapping present,
runtime ports `{"3000/tcp":[]}`, internal network `true`. This is a shared-access
blocker. No `down`, reset, recreation or network bypass command followed it.

## Actual C1 and ZAP parser checks (already performed)

```powershell
docker run --rm --network none --mount "type=bind,source=$phase4Repo,target=/phase4/src,readonly" --mount "type=bind,source=$phase4Bench,target=/phase4/benchmarks" --entrypoint python penagent-sis:local -B /phase4/benchmarks/scripts/check_c1.py
New-Item -ItemType Directory -Force benchmarks/local/zap-import
docker run --rm --network none --mount "type=bind,source=$phase4Bench,target=/phase4/benchmarks" --entrypoint python $phase4Zap -B /phase4/benchmarks/scripts/check_zap.py
```

C1 output: ingestion/graph evidence saved, no target requests or persistent service
writes. ZAP output: offline imports recorded, zero scans, zero real-target requests.
Before creating the log directory, ZAP's first attempt failed before daemon launch;
that harness prerequisite was then corrected. The successful import used only an
inert internal capture fixture and disabled both scan rule sets. Reports:
`specs/validation/c1-{b2b,readonly,limitations}.json`,
`specs/validation/zap-{b2b,readonly}.json`. Generated capture-only JSON and daemon log
are under `local/zap-import/`; their transformation hashes are in mapped evidence.

## Finite benign live route observations (completed; do not repeat automatically)

```powershell
& $phase4Python -B benchmarks/scripts/check_live.py
```

This checks the new image/running/internal-network identity and configured binding,
then uses `docker exec ... /nodejs/bin/node --input-type=module -e <fixed fetch script>
<reviewed path>` for five fixed target-loopback GETs. The exact fetch implementation
is in the script. No shell is started in the container, no target files are written,
redirects are disabled and the fetch has an eight-second timeout. It requests only:

```text
GET /rest/admin/application-version
GET /rest/languages
GET /rest/products/search?q=apple
GET /rest/products/1/reviews
GET /rest/country-mapping
```

The initial `node` lookup failed before requests; changing to the verified absolute
binary resolved it. A subsequent Windows CP1252 decoding failure occurred on the
languages response after version/languages requests. Explicit UTF-8 fixed that.
Final completed output: four 200/JSON responses (version 20.0.0), then country
mapping 500/empty. Final evidence includes response hashes, not raw response bodies:
`specs/validation/live-juice20.json`. Seven benign GETs occurred across the decoding
attempt and final attempt, all to the new target loopback. No attack was attempted.

## Evidence derivation and regressions

```powershell
& $phase4Python -B -m benchmarks.build_readiness
& $phase4Python -B benchmarks/scripts/verify_phase4.py
```

Build output: documented 6; C1 parsed 6, equivalent public paths 5; ZAP imported 6;
successful live 4; currently eligible 0; excluded 6; not live exercised 1; live
failure 1; candidates after connectivity/scope fix 4. All target manifests validate.

`verify_phase4.py` records actual argv/stdout/stderr/exit codes in
`specs/validation/regressions.json`. It executes exactly:

```powershell
& $phase4Python -B -m unittest discover -s benchmarks/tests -v
& $phase4Python -B -m unittest discover -s baselines/zap/tests -q
docker run --rm --network none --mount "type=bind,source=$phase4Repo,target=/phase4/src,readonly" --workdir /tmp --entrypoint python penagent-sis:local -B -m pytest /phase4/src/c1-spec-ingestion/tests/test_graph_builder.py /phase4/src/c1-spec-ingestion/tests/test_tagger.py /phase4/src/c1-spec-ingestion/tests/test_storage_drift.py -q -p no:cacheprovider
```

Results: **36 passed**, **72 passed**, **4 passed** respectively; all exit 0.
The C1 suite emits one upstream FastAPI/httpx deprecation warning. Its same selected
tests were also run once independently with 4 passed before the recorded run.

The verifier also compares all 134 original file hashes (27 smoke artifacts), and
performs read-only `docker inspect` plus
`docker exec <name> /nodejs/bin/node -p "require('/juice-shop/package.json').version"`
on both Juice containers. Full actual argv/output is in `target-identities.json`;
expected/observed identity JSON files are preserved alongside it. Both match;
preservation reports no missing/changed files. No test sends scan traffic.

## Final offline checks and review commands

```powershell
& $phase4Python -B -m benchmarks validate-spec benchmarks/specs/prepared/juice-shop-20.0.0-b2b-host.json --full
& $phase4Python -B -m benchmarks validate-spec benchmarks/specs/prepared/juice-shop-20.0.0-readonly-host.json --full
& $phase4Python -B -m benchmarks validate-manifest benchmarks/manifests/juice-shop-20.0.0.json
& $phase4Python -B -m benchmarks validate-manifest benchmarks/manifests/dvws-original.json
& $phase4Python -B -m benchmarks validate-manifest benchmarks/manifests/srebench-api.json
& $phase4Python -B -m benchmarks audit --out benchmarks/specs/validation/prerequisites.json
& $phase4Python -B -m benchmarks readiness --out benchmarks/specs/validation/readiness.json
git diff --check
git status --short
```

These check stored evidence only. Expected statuses: PARTIALLY READY, BLOCKED,
BLOCKED; prerequisites lists present preparation artifacts, not verified runnable
DVWS/SREBench environments. `git diff --check` covers tracked diffs; new benchmark
Python/JSON files additionally receive syntax/JSON/whitespace checks. No source
changes followed the successful regression run except documentation/recording.

The report distinguishes passed checks, actual failures, missing assets and checks
not executed. Do not interpret a CLI success as authorization or shared live coverage.
