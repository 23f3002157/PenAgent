# Phase 4B PowerShell commands and evidence

Working directory: `C:\Users\Kushi KKS\PenAgentGenAi\PenAgent`.
The commands below were executed; they are a record, **not an instruction to repeat
live checks**. The connectivity entrypoint refuses already-attempted output/control
directories. Both attempts and the failed original-runtime retrieval are preserved.

```powershell
$phase4bPython = 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$phase4bRepo = 'C:\Users\Kushi KKS\PenAgentGenAi\PenAgent'
$phase4bBench = Join-Path $phase4bRepo 'benchmarks'
$phase4bZap = 'ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6'

git status --short
docker ps --format '{{.Names}} {{.Image}} {{.Ports}}'
docker network ls --format '{{.Name}} {{.Driver}}'
docker inspect --format '{{.Name}} {{json .NetworkSettings.Networks}} {{json .NetworkSettings.Ports}}' penagent-phase4-juice20-r1-target-1
docker image inspect --format '{{.Id}}' penagent-executor:local
docker network inspect --format '{{json .Options}} {{json .IPAM.Config}} {{.Internal}}' penagent-phase4-juice20-r1_isolated
& $phase4bPython -B benchmarks/phase4b/snapshot.py
```

Snapshot output: **208 preserved existing file hashes**. Initial/final Git status:
`?? baselines/` and `?? benchmarks/`. No tracked file edits or commit/push occurred.

## Connectivity-only checks

```powershell
& $phase4bPython -B -m unittest benchmarks.phase4b.test_gateway -q
& $phase4bPython -B benchmarks/phase4b/connectivity.py
& $phase4bPython -B benchmarks/phase4b/connectivity.py r2
```

The first sandbox test run failed on temporary-directory permissions; the same
authorized outside-sandbox test run passed all 12 gateway tests. The r1 connectivity
attempt passed PenAgent runtime requests but failed ZAP's initial 30-second readiness
wait during certificate creation. It forwarded 5 and blocked 3. The r2 readiness
wait is bounded at 90 seconds and the ZAP client gets two CPUs; the **same overall
180-second deadline/10-second reserve** remains enforced. R2 passed in **37.859 s**,
forwarding 10 and blocking 6. No active/Full Scan/spider/Executor probe API is called.

Full actual Docker argv, stdout, stderr, resource names and cleanup ownership checks:

- `phase4b/evidence/connectivity-run.json` (failed r1 preserved).
- `phase4b/evidence/connectivity-r2/connectivity-run.json` (successful r2).
- Matching `connectivity-config.json`, `penagent-connectivity.json`,
  `zap-connectivity.json`, `gateway-policy.json`, gateway clock records,
  `gateway-traffic.jsonl`, `gateway-summary.json` in the same evidence directories.

Only run-owned labeled containers were stopped, and they/networks were retained.
The gateway permits exactly the five reviewed GET examples listed in its source,
not arbitrary requests to those paths. Negative connections send no HTTP/application
payload. Both real targets remain running with unchanged identity/configuration.

The final gateway code additionally replaces construction-time `assert` checks with
explicit `ValueError` validation. This hardening does not change the permitted paths,
queries, deadlines or forwarding behavior used by either connectivity attempt; the
final code passed all gateway tests. Earlier run evidence was not overwritten.

## Authentic DVWS sources and original runtime feasibility

```powershell
& $phase4bPython -B benchmarks/phase4b/collect_sources.py
docker manifest inspect --verbose php:5.5.38-apache
& $phase4bPython -B benchmarks/phase4b/check_legacy_runtime.py
& $phase4bPython -B benchmarks/phase4b/prepare_candidates.py
```

Source collection downloads **only** commit-pinned archives, verifies safe archive
paths, hashes every file and saves public metadata. It executes no downloaded code.
Original commit: `25a5a03aa1b13d8e647da66784c3e8445726e578`; successor commit:
`35f999505028f580dd6acc8bb7ddecfb87fe4bf6`. Download URLs and all captured file hashes
are in `phase4b/evidence/upstream-archives.json`; actual source archives/extractions
remain ignored under `benchmarks/local/phase4b/upstream/`.

Queries include GitHub profile/repository searches, the original history through
2019-12-31, and read-only manifests for official PHP and both claimed SRE image names.
The SRE manifests returned denied/unauthorized; no SRE image was pulled or deployed.

The runtime checker resolves the official PHP descriptor, then attempts exactly:

```powershell
docker pull php@sha256:be7f9332d3bea49084d74a0718a5400f7b5d128c1937575e76f72df3a41e8eac
```

Result: exit 1, content-store/layer extraction NotFound; exact argv/output in
`phase4b/evidence/legacy-runtime.json`. No original application build/run followed.
Do not replace this observed error with an unsupported-format or remote-deletion
claim. There was no Docker reset/cache clean or unknown-image fallback.

Preparation output: 52 successor operations, initial source-validation failure.
The body-parameter defect remains in the unchanged raw/semantic source copies.

## Successor parser checks: inert fixture, no deployment/adoption

```powershell
docker run --rm --network none --mount "type=bind,source=$phase4bRepo,target=/phase4/src,readonly" --mount "type=bind,source=$phase4bBench,target=/benchmarks" --workdir /tmp --entrypoint python penagent-sis:local -B /benchmarks/phase4b/check_candidate_c1.py
docker run --rm --network none --cpus 2 --memory 2g --mount "type=bind,source=$phase4bBench,target=/benchmarks" --entrypoint python $phase4bZap -B /benchmarks/phase4b/check_candidate_zap.py
& $phase4bPython -B benchmarks/phase4b/finish_candidates.py
```

Outputs: C1 `PARSED`, 52 operations; ZAP `IMPORT_RETURNED`, errors `[]`, 52 inert
fixture examples, zero real target requests and empty active/spider lists. The
independent complete OpenAPI validator returns **one schema error**, preserved in
`dvws-node-schema-errors.json`. No repair, credentials, DB seeding, live target or
adoption is implied by permissive parser success. Historical resolution, raw byte
hash and explicit parser/template comparison are saved by `finish_candidates.py`.

## SREBench source review and non-executable planning

```powershell
& 'C:\Users\Kushi KKS\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\poppler\Library\bin\pdftoppm.exe' -scale-to 1800 -png 'images/SREBench API.pdf' 'benchmarks/local/phase4b/pdf/scenario'
& $phase4bPython -B benchmarks/phase4b/scenarios.py
& $phase4bPython -B -m benchmarks.phase4b.registry
```

All six rendered source pages were visually reviewed. Outputs: 20 catalog IDs;
five detailed mechanisms needing interpretation; fifteen title-level cases with
insufficient information. Registry output: all three families retained, original
DVWS retained, successor/reproduction unadopted. SRE plan/contract gaps are JSON
documents only; there are no scenario service implementations, Dockerfiles or
invented executable OpenAPI endpoints in the reproduction directory.

## Final tests and configuration-only checks

```powershell
& $phase4bPython -B benchmarks/phase4b/verify.py
```

The verifier executes and records:

```powershell
& $phase4bPython -B -m unittest benchmarks.phase4b.test_gateway benchmarks.phase4b.test_readiness -v
& $phase4bPython -B -m unittest discover -s benchmarks/tests -v
& $phase4bPython -B -m unittest discover -s baselines/zap/tests -q
docker run --rm --network none --mount "type=bind,source=$phase4bRepo,target=/phase4/src,readonly" --workdir /tmp --entrypoint python penagent-sis:local -B -m pytest /phase4/src/c1-spec-ingestion/tests/test_graph_builder.py /phase4/src/c1-spec-ingestion/tests/test_tagger.py /phase4/src/c1-spec-ingestion/tests/test_storage_drift.py -q -p no:cacheprovider
```

Actual results: **34 + 36 + 72 + 4 = 146 passed**. One upstream FastAPI/httpx
deprecation warning in C1. Missing historical datasets, external model APIs, live
PenAgent vulnerability workflows and all active experiments are not run or counted.

It also runs `docker compose -f benchmarks/phase4b/deploy/juice-fresh.compose.yml
config --quiet` with unique validation-only project/volume names and absolute
benchmark/control paths. This returns 0 and does not create those resources.
It inspects both existing Juice containers, validates the registry, parses new
Python/JSON files and checks all 208 preserved existing hashes. Full argv/output,
IDs and results are in `phase4b/evidence/verification.json`.

Final review commands:

```powershell
& $phase4bPython -B benchmarks/phase4b/finalize.py
git diff --check
git status --short
```

The finalizer checks new-document links/JSON/Python, preservation, registry and
artifact hashes. It performs no Docker/network actions. `git diff --check` covers
tracked changes; new text files receive separate trailing-whitespace/syntax checks.
No existing baseline manifest, source/evidence file or container was overwritten,
deleted or reset. Only new Phase 4B files were developed during this task.
