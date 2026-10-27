# Phase 4B completion — 2026-10-25

**Final status: PARTIALLY READY — APPROVALS REQUIRED.** All three mandatory
families have explicit records and resolutions/blockers. Juice Shop shared benign
access is fixed and verified. Original DVWS runtime retrieval failed; its successor
is a concrete unadopted proposal. SREBench has a source-traced, non-executable
reproduction plan requiring approval and missing-contract decisions. Technical
blockers remain alongside those approvals; no target is claimed fully ready for
the complete research comparison.

The existing Phase 4 reports remain historical evidence. All new implementation
and evidence are under `benchmarks/phase4b/`, plus this new report. Existing Phase 4,
Components 1–4 and the ZAP baseline were not edited. The unified machine-readable
registry is `phase4b/registry.json`; its exact record contract is enforced by
`phase4b/registry.py`, with separate manifests under `phase4b/manifests/`.

## 1. Summary and readiness matrix

| Benchmark | Source type | Runnable | OpenAPI | Shared tool access | Reproducible state | Status |
|---|---|---|---|---|---|---|
| Juice Shop 20.0.0 | ORIGINAL | Existing separate pinned target running | Official B2B 1 + non-official subset 5, valid; deliberately incomplete | Actual five benign GET examples through same gateway, four successful | Fresh independent-volume configuration prepared and syntax-validated; seed equivalence not exercised | PARTIALLY READY |
| Original DVWS | ORIGINAL | Not deployed; official legacy runtime retrieval/extraction failed | No original OpenAPI located; no invented substitute spec | Not executed | Original setup/source inspected, blocked before build | BLOCKED |
| DVWS-Node candidate | SUCCESSOR | Not built/deployed/adopted | 52 documented operations; one actual schema error; both parsers accept 52 offline | No live target; inert fixture only | Destructive seed reviewed; dedicated-volume proposal only | REQUIRES APPROVAL |
| SREBench-API proposal | REPRODUCTION | No service implemented | Partial source examples only; executable spec missing | Not executed | Non-executable seed/reset design only | REQUIRES APPROVAL |

The DVWS-Node row is a candidate within the DVWS family, not a fourth mandatory
family and not a silent replacement. No successor/reproduction is called official.
No active scan, PenAgent vulnerability probe, comparative experiment, repeat series
or ground-truth adjudication ran.

## 2. Juice Shop: diagnosis, fix and verified access

### Exact diagnosis

The Phase 4 target `penagent-phase4-juice20-r1-target-1` is healthy on its own
container loopback, but its internal-only network has no effective host publication:
HostConfig requests `127.0.0.1:18001:3000`; NetworkSettings shows `3000/tcp: []`.
Consequently neither host origin nor `host.docker.internal:18001` provides the
previously assumed access path. C1 is an ingestion/graph service, not a target
request engine. Existing C1/C3 services are on the PenAgent control/provider
networks; they were not attached to the private target network or reconfigured.
The old ZAP runner's fixed host-mapping contract also cannot use the private target
origin directly. No Windows firewall, Docker daemon setting or public bind was changed.

### Actual minimal fix

Use a new two-interface **connectivity-only** gateway: one interface on the existing
target's internal network, the other on a newly created internal tool network with
Docker `gateway_mode_ipv4=isolated`. Tools attach only to the tool network; the
target remains on its original single network. No host ports are published, no
public exposure is introduced, and no existing container configuration changes.
This follows Docker's documented internal-network and isolated bridge semantics:
[network creation](https://docs.docker.com/reference/cli/docker/network/create/),
[gateway modes](https://docs.docker.com/engine/network/port-publishing/).

The successful path, recorded from actual inspections, is:

```text
ephemeral PenAgent runtime / ZAP proxy
  -> 172.26.0.1:8088 (gateway, tool network penagent-phase4b-tools-r2)
  -> 172.24.0.2:3000 (verified target, penagent-phase4-juice20-r1_isolated)
```

Measured addresses are run-specific; `phase4b/evidence/connectivity-r2/connectivity-config.json`
is authoritative. Future runs must rediscover them rather than assume those values.
The target and gateway are distinct origins. The gateway permits exactly five
reviewed benign GET request-targets, including fixed `q=apple` and review ID `1`;
it rejects other methods, query mutations, credentials, bodies and alternate paths.
It is capped at 20 forwarded requests with a monotonic 180-second overall runner
budget and 10-second cleanup reserve, conservative gateway clock handshake and
permanent forwarding revocation. This is stricter connectivity scope, not a change
to the original smoke scan's 100-request policy.

### Actual checks and limits of proof

The PenAgent check used a new container from the existing C3 image by immutable
local image ID, its installed `httpx` client with C3's transport settings, and the
actual numeric-origin guard. It did **not** call `Executor.execute`, probe/workflow
APIs, existing C1 HTTP ingestion endpoints or production service databases. It
proves access for the isolated PenAgent runtime layout, not an end-to-end deployed
PenAgent security workflow. Existing services remain unchanged.

ZAP 2.17.0 performed actual HTTP proxying of only the fixed benign GETs, in safe
mode with every active/passive rule disabled. Its active/spider scan lists are
empty. Before either client's GETs, TCP-only isolation checks confirmed no direct
target access, no original-target bypass, no host-service access on tested
9001–9004/target ports, and no tested external connection. No application payload
was sent on these negative connection attempts. Untested destinations are covered
by topology/configuration, not claimed as an exhaustive empirical network proof.

The first attempt (`r1`) passed the PenAgent checks but ZAP's initial certificate
creation exceeded the initial readiness wait. It forwarded 5 GETs, blocked 3 and
failed before ZAP target requests. Its evidence is retained. A separate `r2`
connectivity attempt increased readiness allowance/CPU while retaining the overall
deadline. It succeeded in **37.859 seconds**, forwarding **10 GETs**, blocking **6**,
and returning identical response hashes to both clients. Total across Phase 4B's
two connectivity attempts: **15 forwarded benign GETs and 9 blocked requests**.
These are connectivity attempts, never repeated scans. The r2 last-request summary
shows `closed: false`; final run metadata separately confirms the later revocation
marker and shutdown. It is not a post-shutdown status snapshot.

Only newly created labeled gateway/client containers were stopped; they and the
new tool networks were retained as evidence. Both original Juice Shop containers
remain running with unchanged IDs/images/networks/ports. No Docker cleanup/reset
or daemon restart was attempted.

### Six-operation inventory

| Method / public path | Source | Actual behavior | Auth | C1 / ZAP | Comparative eligibility |
|---|---|---|---|---|---|
| GET /rest/admin/application-version | Non-official, source-derived | Both clients 200, version 20.0.0 | Anonymous | Parsed / imported | Limited candidate |
| GET /rest/languages | Non-official, source-derived | Both clients 200/JSON | Anonymous | Parsed / imported | Limited candidate |
| GET /rest/products/search | Non-official, source-derived | Both clients 200 with q=apple | Anonymous | Parsed / imported | Limited candidate; active query policy not authorized |
| GET /rest/products/{id}/reviews | Non-official, source-derived | Both clients 200 for id=1 | Anonymous | Parsed / imported; template maps to concrete example | Limited candidate; wider inputs unverified |
| GET /rest/country-mapping | Non-official, source-derived | Both clients 500, expected missing CTF configuration | Anonymous | Parsed / imported | Excluded |
| POST /b2b/v2/orders | Official v20.0.0 B2B YAML | Source reviewed; never invoked | Bearer, unverified role/token | Parsed, C1 loses /b2b/v2; ZAP imported offline | Excluded: state/code-execution semantics, auth and base-path mismatch |

Current specs and C1/ZAP source/report bytes match preserved Phase 4 evidence;
schema validations reran in the existing benchmark tests. The new inventory is
`phase4b/juice-inventory.json`. Four operations qualify for limited ground-truth
preparation; **no operation is authorized for active execution**. The six-operation
collection is a small connectivity/ingestion subset, not meaningful coverage of the
full Juice Shop API, authenticated business flows or cross-service exploit chains.
Response models remain partial and most candidates do not expose a rich attack
surface. A primary full research benchmark cannot be inferred from these counts.

### Fresh-instance reproducibility

`phase4b/deploy/juice-fresh.compose.yml` pins the approved image digest and prepares
separate internal target/tool networks, no public ports, resource/capability limits,
a version health check and an independently named `/juice-shop/data` volume.
Fresh project and volume names are mandatory inputs. Compose configuration
validation passed without creating a container or volume from that file.

Default image-seeded DB/data is the intended initial state; named-volume copy-up,
permissions, initialization and state equality have **not** been exercised. Before
repeats, verify seed snapshots/version/schema hashes and identical permitted roles
for each tool. “Reset” means allocate a new independent project/volume, never reset
or reuse either existing container as evidence of clean state. Anonymous is the only
verified role. The approved smoke manifest and its raw reports remain unchanged.

The existing baseline runner still requires a separately reviewed private-network
adapter, identity binding and active-input scope. The connectivity gateway rejects
all parameter mutations and must not be presented as an active scanning gateway.
`phase4b/comparison-plan.json` records equal candidate operations, roles, exclusions,
proposed 180-second/100-forwarded-request budgets, independent future repeats and
raw evidence requirements; none of those experiments ran.

## 3. Original DVWS and successor comparison

### Identity and history

The operator confirmed [snoopysecurity/dvws](https://github.com/snoopysecurity/dvws)
as the authoritative original project, and its README explicitly identifies
[DVWS-Node](https://github.com/snoopysecurity/dvws-node) as the successor. GitHub's
maintainer profile identifies **Sam Sanoop**. This relationship is verified; the
proposal's exact **“Beebs (2019)” attribution remains unconfirmed**.

The original repo was created 2016-01-12. A bounded history query through
2019-12-31 returns commit `7a4af27dbcd40c6c7aeee84bb388ff209203be6e`, dated
2016-12-03. Latest archived-source pin is
`25a5a03aa1b13d8e647da66784c3e8445726e578` (last push 2021-12-06); the repository
was archived 2023-08-17 and exposes no release/tag version in the observed API
results. These are source revisions, not a fabricated 2019 release or experimentally
verified last-compatible runtime. Source evidence and exact history query are in
`phase4b/evidence/dvws-source-resolution.json` and `source-searches.json`.

The complete pinned original archive (78 files) was captured for static review;
archive/file hashes and exact URLs are recorded. README requires PHP **5.5.38**,
XAMPP/Apache/MySQL and its setup PHP. Original NuSOAP, XML-RPC, REST SQLi, JWT,
XML/SSRF/CORS/command-injection exercises are real source, not a synthetic replacement.
PHP entrypoint filenames are listed separately and not miscounted as tested API
operations. No authoritative original OpenAPI definition was found in that tree.

### Concrete original deployment attempt/blocker

The official `library/php:5.5.38-apache` manifest resolves to
`php@sha256:be7f9332d3bea49084d74a0718a5400f7b5d128c1937575e76f72df3a41e8eac`,
linux/amd64. Exact-digest retrieval was attempted once and failed before a build:

```text
failed to unpack image on snapshotter overlayfs ... NotFound:
failed to get reader from content store:
content digest sha256:357ea8c3d80bc25792e010facfc98aee5972ebc47e290eb0d5aea3671a901cab: not found
```

This is an observed local retrieval/extraction failure, not proof the remote image
or layer is permanently gone, and not a claim of an unsupported manifest format.
No runtime image was executed, no Windows legacy dependencies were installed, and
no alternative third-party image or daemon/cache reset was used.

A digest-pinned `phase4b/deploy/dvws-original.Dockerfile.proposed` records the
possible next build: bundled legacy mysql/mysqli extensions, source copied intact,
unprivileged Apache on an internal port. It was **not built**. Exact-base retrieval,
toolchain availability and local MySQL/socket topology must be restored/verified
first. Static review also found mixed `mysqli_connect` then `mysql_query`, and
undefined write-branch `$set`; upstream mentions manual DB configuration. We did
not repair those branches or change vulnerability logic. A faithful runtime needs
an explicitly documented compatibility assessment, not a rewritten modern service.
README claims GPL-3 while LICENSE is Apache-2.0; redistribution of a derived image
must wait for clarification of that conflict.

### Successor candidate and recommendation

| Attribute | Original DVWS | Proposed DVWS-Node |
|---|---|---|
| Source identity | Original PHP project; citation attribution uncertain | Separately maintained explicit successor |
| Proposed source pin | Archived 25a5a03… for feasibility; historical 7a4af27… recorded | 35f999505028f580dd6acc8bb7ddecfb87fe4bf6 |
| Runtime | PHP 5.5.38 / Apache / local MySQL | Node >=22 <23 / MongoDB / MySQL / frontend build |
| Container readiness | Exact official base retrieval failed | No application image built or adopted; upstream uses mutable tags |
| API documentation | PHP exercise source; no original OpenAPI found | Actual upstream OpenAPI describes 52 operations |
| Actual parser results | Not executed, missing valid original spec/runtime | C1 52 parsed, ZAP 52 mapped, no live target |
| Full OpenAPI schema | Missing | **Failed: one schema error** |
| Repeatability | Setup/source inspected, not executed | Seed script drops/recreates DB/data; dedicated new volumes required |
| License metadata | LICENSE Apache-2.0 / README GPL-3 | LICENSE GPL-3 / package.json MIT |

The actual successor OpenAPI mixes an OAS2-style `in: body` parameter into its
OAS3 POST `/v2/resource-store/orders`. An independent full validator reports one
error at `parameters/0`; C1 and ZAP nevertheless accept 52 operations. We preserved
the defect and raw upstream bytes, rather than weakening validation or quietly
converting the schema. C1 additionally loses the `/api` server base. ZAP import
ran with `--network none`, safe mode and all rules disabled; its 52 requests went
only to an inert loopback fixture. No successor target was contacted/deployed.

Candidate artifacts: raw upstream bytes, semantic JSON copy, origin-only prepared
copy, operation inventory, parser/schema reports, and an explicitly proposed
internal-only Compose template requiring reviewed image digests and fresh volume
names. No image build/pull, account creation, seed execution or auth test ran for
DVWS-Node. Source review identifies state-changing GETs; GET is not assumed safe.

**Recommendation:** retain original DVWS as preferred if its exact runtime can be
restored faithfully. Otherwise approve **“DVWS-Node — proposed successor benchmark”**
at the pinned commit as a separate target, with documented schema conversion,
base-path handling, dependency/image pinning and isolated initialization validation
before deployment. Its findings must never be represented as original DVWS findings.

## 4. SREBench-API source, feasibility and reproduction plan

The supplied `images/SREBench API.pdf` visually contains exactly **20** scenarios:
SRE-01 through SRE-20. It has five detailed mechanism sections (01, 02, 03, 12,
16); the other fifteen are catalog-level titles/chains/categories only. The source
hash and page references are attached to every row in
`phase4b/srebench/scenario-matrix.json`; the readable table is
`phase4b/srebench/SCENARIO_MATRIX.md`.

Exact-name external searches, GitHub repository searches and local inspection did
not establish a genuine released executable benchmark, dataset archive, runnable
harness, image digest or deployable OpenAPI. Unrelated incident-response and reverse-
engineering SRE-Bench projects are documented as nonmatches, not substitutes.
The supplied PDF p.6 claims `penagent-target-env:latest`, `/scenarios/list`,
`specs/srebench_openapi.json` and `datasets/ground_truth_chains.json`; those assets
are not present. The repository README names `monisha117/penagent-test-env:latest`.
Read-only manifest queries for both names returned denied/unauthorized, which means
**not accessible/verified**, not proven nonexistent. No login credentials were
requested/exported, no image was pulled, and no official runnable discovery was
deployed. Exact query/results are preserved in source-search/image-manifest evidence.

Every matrix row includes the actual title, source pages/hash, intended behavior,
reported vulnerability category/depth/CVSS, state, auth, source-explicit endpoints,
observable effect, ambiguities, missing details, feasibility and fidelity confidence.
**Five REQUIRES INTERPRETATION; fifteen INSUFFICIENT INFORMATION; zero SPECIFIED
ENOUGH TO REPRODUCE as a faithful executable benchmark.** Reported scores and
claimed “ground-truth sequences” are source descriptions, not adjudicated labels.
The PDF's architecture illustration is blank and endpoint/schema/state details are
incomplete; titles alone do not authorize inventing a vulnerability implementation.

`phase4b/srebench/reproduction-plan.json` is non-executable and explicitly labeled
**“Local reproduction based on the research proposal.”** It proposes isolated
service boundaries, a separate experiment safety gateway, deterministic approved
seeds, new per-run volumes, scenario/source traceability, infrastructure health
checks and reset outside scanner scope. It introduces no scenario routes or service
code. The source supplies no vulnerability-toggle design; none is implemented or
claimed. Cloud/IdP/payment dependencies would need source-approved local substitutes,
never real cloud metadata or production integrations. Partial route examples are
kept in `contract-gaps.json`, explicitly **not** a fabricated OpenAPI specification.

## 5. Exact manual decisions and next actions

Only the following decisions require operator involvement:

1. **DVWS family:** keep pursuing original runtime restoration, or explicitly adopt
   the pinned **proposed successor** with its documented differences. The successor
   is unadopted until approved; original-project identity no longer needs clarification.
   The “Beebs” attribution can remain an explicitly recorded bibliographic uncertainty.
2. **SREBench:** provide genuine accessible assets/source, or approve the scenario
   matrix and reproduction methodology. Resolve/approve the listed contract and
   behavior choices, especially the fifteen catalog-only cases, before any vulnerable
   services are implemented. Matrix approval alone does not make missing details known.

After those decisions, the concrete technical sequence toward all three running is:

- Juice Shop: validate a **new** instance/volume's deterministic seed state, preserve
  the four-operation limited scope or approve documented expansion, then prepare
  a private-network baseline adapter and reviewable active-input policy. Existing
  services/targets need no network/public-port change. Active execution remains a
  separate future approval; no scan is needed to resolve preparation items.
- Original DVWS: restore a usable exact official PHP image or audit a faithful
  pinned rebuild; verify extensions, local MySQL/socket behavior and original
  APIs without silently repairing vulnerabilities. If that remains blocked, use
  the approved successor route only after the decision above.
- Approved DVWS-Node: resolve license metadata, convert the one invalid body
  declaration with traceability, preserve `/api`, lock/build reviewed dependencies
  and images, provision **new** Mongo/MySQL volumes, and validate initialization,
  roles and benign shared access. Do not run its seed script against existing DBs.
- Approved SREBench reproduction: freeze approved scenario contracts and source
  deviations, then implement only approved behavior in isolation, produce genuine
  derived OpenAPI, and validate state/auth/tool access. None is implemented now.

These are concrete remaining steps, not claims that all three environments exist.

## 6. Tests and verification

| Executed check | Actual result |
|---|---|
| New Phase 4B gateway/readiness/provenance/traceability tests | **34 passed** |
| Existing Phase 4 benchmark suite | **36 passed** |
| Existing ZAP safety suite | **72 passed** |
| Relevant existing C1 graph/tag/storage-drift regressions | **4 passed**, one upstream FastAPI/httpx deprecation warning |
| Fresh Juice Compose `config --quiet` | Passed; no new volume/target started |
| Actual Juice shared connectivity r2 | Passed; 10 forwarded, 6 denied, 37.859 s |
| Original PHP exact-digest pull | **Failed**, preserved content-store/layer extraction error |
| Successor full OpenAPI validation | **Failed**, one upstream body-parameter schema defect |
| Successor C1 / ZAP offline import | 52 parsed / 52 mapped; no target or auth validation |
| SRE source traceability | 20 verified catalog IDs; no runnable-asset or fidelity claim |
| Existing preservation hashes | **208 unchanged**, including earlier 27 smoke artifacts |

Tests validate honest reporting of blockers; expected source/runtime defects are
not relabeled as successful validations. The initial sandbox unit-test attempt
could not write temporary fixtures; the authorized outside-sandbox run passed.
The actual r1 ZAP startup failure and all source defects remain preserved.

Checks **not executed**: original/successor application builds and live APIs, fresh
volume seed/reset equivalence, authenticated workflows, SRE scenario services,
full deployed PenAgent workflow, active scans, comparative repeats, model API
tests, historical C1 tests needing missing datasets and Phase 5 adjudication.

Exact commands/stdout/stderr are in `phase4b/evidence/verification.json`, both
`connectivity-run.json` records, candidate reports and `legacy-runtime.json`.
[PHASE4B_COMMANDS.md](PHASE4B_COMMANDS.md) provides the PowerShell sequence. Both
Juice container identities/images/running states were rechecked. No existing
containers were deleted/reset; no Components 1–4 or existing baseline/approved
manifest files changed; no private credentials were exported; no commit/push ran.
The failed base pull may leave Docker-managed download data; it was not cleaned.

## 7. Remaining blockers and Phase 5 readiness

Highest impact: (1) missing SRE executable contracts and approval; (2) original DVWS
runtime retrieval and successor decision/schema/deployment; (3) fresh-state equality
and the future private-network active-runner adapter for Juice Shop; (4) broader
authenticated/API coverage and license metadata clarifications.

Juice Shop's **four reviewed candidates** can enter limited source-based vulnerability
ground-truth preparation after a separately requested Phase 5 task. Original DVWS,
the unadopted successor and SRE reproduction are not ready for executable ground-
truth preparation or comparison. No ground-truth labels were adjudicated here.
All authorized Phase 4B preparation is finished; stop at the documented approval
boundaries. The result is not ALL THREE BENCHMARKS READY.
