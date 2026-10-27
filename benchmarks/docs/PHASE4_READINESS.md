# Phase 4 readiness — 2026-10-25

## 1. Executive summary and readiness matrix

Phase 4 preparation and non-attacking verification are complete. All three proposed
targets still have blockers; no API-level benchmark or ground-truth phase started.

| Target | Deployment | OpenAPI | PenAgent | ZAP | Shared eligible operations | Overall |
|---|---|---|---|---|---|---|
| Juice Shop 20.0.0 | New isolated instance running; host port unpublished | Official B2B 1 + explicitly non-official subset 5; schema-valid | 6 parsed, 5 public paths equivalent | 6 imported in offline capture fixture | 0 currently; 4 candidates after connectivity/scope work | PARTIALLY READY |
| Original DVWS | Source candidate exists; reproducible compatible runtime not established | No authoritative OpenAPI located | Not executed | Not executed | Unknown, no validated operation set | BLOCKED |
| SREBench-API | Scenario descriptions; no executable assets located | Missing | Not executed | Not executed | Unknown, no validated operation set | BLOCKED / NEEDS IMPLEMENTATION |

**Original DVWS is not usable as the requested reproducible API benchmark in its
present verified state.** Source is available, but citation identity, legacy runtime,
container reproducibility and an applicable specification remain unresolved.
An explicitly documented substitution with DVWS-Node is recommended for a separate
approval decision and subsequent validation. It has not been adopted or deployed.

## 2. Benchmark source audit

The initial repository audit is [AUDIT.md](AUDIT.md). Machine-readable captured
metadata is `sources/audit-summary.json`; pinned complete repository tree listings
are in `sources/repository-index.json`. Research used the supplied proposal PDF and
the repository's scanned `images/SREBench API.pdf`, alongside upstream material.

**Juice Shop.** [OWASP/juice-shop repository](https://github.com/juice-shop/juice-shop)
is active (observed push 2026-10-23), MIT licensed, with intentionally seeded
challenges. The deployed and source-verified version is
[v20.0.0](https://github.com/juice-shop/juice-shop/releases/tag/v20.0.0), tag commit
`f356a09207c7a9550eb6fc4c3945e081922cf998`. Later releases were observed but not used.
The image is `bkimminich/juice-shop@sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f`.
Selected deployed source files matched authoritative v20.0.0 bytes exactly; see
`sources/juice-shop-20.0.0/tag-verification.json`. Default initialization provides
seeded application data; identical challenge state across experiments is unproven.

**Original DVWS candidate.** The proposal's “Beebs (2019)” reference has no URL or
version; authoritative attribution to this candidate remains unresolved.
[snoopysecurity/dvws](https://github.com/snoopysecurity/dvws/tree/25a5a03aa1b13d8e647da66784c3e8445726e578)
is archived; observed last push 2021-12-06, commit
`25a5a03aa1b13d8e647da66784c3e8445726e578`, no tags or releases returned by GitHub.
Its README explicitly requires PHP **5.5.38**, XAMPP/Apache/MySQL, describes a database
setup/reset page, and points users to its successor. Actual PHP SOAP/WSDL, JSON-RPC
and REST exercise source exists; this is not DVWA. No Dockerfile, Compose file,
official image or OpenAPI definition was established from the original project's
tree/documentation. Unrelated community images were not treated as authoritative
or started. The README claims GPL-3, while its LICENSE file is Apache-2.0: record
the conflict rather than silently choosing a license. Vulnerability exercises are
documented; operation-level adjudicated ground truth was not established.

**Separate candidate, REQUIRES APPROVAL, not a target substitution.**
[DVWS-Node](https://github.com/snoopysecurity/dvws-node/tree/35f999505028f580dd6acc8bb7ddecfb87fe4bf6)
explicitly calls itself a replacement for DVWS. It is GPL-3, active (observed push
2026-10-25), commit `35f999505028f580dd6acc8bb7ddecfb87fe4bf6`, no tags/releases returned.
The pinned tree contains Dockerfile, Compose, seed script, tests, and
[docs/openapi/openapi.json](https://github.com/snoopysecurity/dvws-node/blob/35f999505028f580dd6acc8bb7ddecfb87fe4bf6/docs/openapi/openapi.json).
That file declares API version 0.1 and server `http://dvws.local/api`; neither proves
compatibility with the current source. Node 22, MongoDB and MySQL deployment assets
use mutable image tags/build dependencies; a reproducible isolated digest-pinned
build would need review. No official published image digest was established. No
build, pull, deployment, import test, API count or coverage claim was made for it.

**SREBench-API.** The proposal describes a proposed 20-scenario research benchmark.
The local scanned PDF supplies scenario design, not services, containers, datasets
or OpenAPI. Exact-name searches and supplied repository/material inspection did
not locate authoritative runnable assets or a versioned public source. This is a
bounded negative finding, not proof that no private implementation exists. The
unified third-party image mentioned in `images/README.md` is unverified and was not
started. Unrelated similarly named SRE-Bench projects are not substitutes.

## 3. Deployment inventory

Docker Engine/client 29.4.3, Desktop 4.73.1 and Compose 5.1.3 were available.
The original `blissful_chebyshev` remains running, ID
`0356c18439557ca2fed64e8c69f73035c4b485ca069b6f961b1de038f17d9ac3`, version 20.0.0,
image ID equal to the approved digest hash, existing host port 3000 preserved.

A new approved-source instance was created with `deploy/juice-shop.compose.yml`,
project `penagent-phase4-juice20-r1`, container `penagent-phase4-juice20-r1-target-1`,
ID `0710d10e33c5ff2af7248c6c73e4cb446db4de419255bb7b28d1a9280339116c`.
It uses only internal network `penagent-phase4-juice20-r1_isolated`, dropped
capabilities, no-new-privileges, CPU/memory limits, no restart policy, no volumes,
and an intended loopback mapping `127.0.0.1:18001:3000`. No image was pulled.

**Actual runtime failure:** HostConfig records that mapping, but NetworkSettings
reports `3000/tcp: []` and the internal network has no gateway. Host publication is
not established on this Docker runtime. No network attachment/recreation was used
to bypass that result. Safe route checks used Node fetch on the new container's
own loopback only. Configured host/container origins therefore remain unverified
for PenAgent and ZAP. This instance remains running; none were deleted or reset.

## 4. OpenAPI validation

The official [v20.0.0 swagger.yml](https://github.com/juice-shop/juice-shop/blob/v20.0.0/swagger.yml)
is OpenAPI 3.0.0 and describes **one B2B order operation**, POST `/orders` under
relative server `/b2b/v2`. Its **API** info.version 2.0.0 is distinct from application
20.0.0. Target-version correspondence is verified through image/source provenance,
not by forcing these unrelated version fields to match.

Original YAML bytes are retained. Host and Docker JSON preparations change only
server origin and preserve `/b2b/v2`; they do not hide C1 limitations. The dangerous
order operation was never invoked on a target.

The separate non-official derived spec describes exactly five source-reviewed GETs:
version, languages, product search, product reviews and CTF country mapping.
`generate_specs.py` verifies route declarations against captured source and records
handler hashes. Parameters are directly sourced; response schemas are deliberately
partial/open. This is **not** a complete API, authenticated workflow description or
vulnerability dataset. Original/generated and host/Docker copies remain separate.

Both host documents passed `openapi-spec-validator==0.7.2`, including schema refs.
SHA-256 values for every original/prepared copy are in the target manifest and
`specs/validation/spec-hashes.json`; source-file hashes are in source provenance.
Validation JSON records declared parameters, request bodies, security and routes.

## 5. PenAgent compatibility

The actual existing C1 `SpecNormalizer` and `GraphBuilder` ran offline from the
read-only repository mount with no DB writes. Results: **6/6 source-spec operations
parsed**, methods/parameters/body/auth captured, IDs stable across duplicate builds,
no dropped operations in these two documents. Evidence: `c1-b2b.json`,
`c1-readonly.json`, `c1-limitations.json` in `specs/validation/`.

Classified **PenAgent ingestion limitations**, not repaired in this phase:

- The B2B server base `/b2b/v2` is ignored: graph path `/orders` differs from actual
  `/b2b/v2/orders`. Thus only **5/6** public method/path representations agree.
- Request-body required/media metadata is not retained by graph schema storage.
- Multi-scheme/security alternatives reduce to the first scheme/requirement.
- A labeled synthetic TRACE fixture produces zero graph nodes, and distinct
  operationIds `A-B`/`A_B` produce colliding graph IDs. These are parser test cases,
  not benchmark operations. Actual prepared spec IDs do not collide.

No component, production graph, PenAgent policy or stored session was changed.

## 6. ZAP compatibility

Actual pinned ZAP **2.17.0** imported both prepared documents in a fresh container
with `--network none`, safe mode, all active and passive rules disabled. Import
generated examples only against an inert loopback capture fixture inside that
container; it could not reach Juice Shop, PenAgent or external destinations.
ZAP recorded **1 B2B POST + 5 GET example requests**, import errors `[]`, active
scans `[]`, spider scans `[]`, real-target requests **0**. No Full Scan ran.

The origin-only capture transformation and SHA-256 are recorded in
`zap-*-mapped.json`; exact transformed documents/log remain under ignored
`local/zap-import/`. Raw `zap-readonly.json` lists concrete `/rest/products/1/reviews`
and initially reports the template absent. The separate mapped evidence matches
that example to the unique declared template `/rest/products/{id}/reviews`,
without overwriting raw evidence or counting it twice. All **6/6** operations map.
Import success does not prove target access, bearer authentication or coverage.
See [ZAP OpenAPI documentation](https://www.zaproxy.org/docs/desktop/addons/openapi-support/).

## 7. Common operation inventory

Machine-readable per-operation records: `inventories/juice-shop-20.0.0.json`.
Comparison: `inventories/comparison.json`. Methods and template paths remain distinct.

| Measure | Actual count |
|---|---:|
| Documented operations in the limited two-spec collection | 6 |
| Parsed by C1 / equivalent public paths | 6 / 5 |
| Imported by ZAP after explicit template mapping | 6 |
| Successful live reviewed GET examples on target loopback | 4 |
| Live GET failure | 1 |
| Operation not live exercised | 1 |
| Currently shared eligible | 0 |
| Excluded from a current primary comparison | 6 |
| Candidates after connectivity and enforced-scope work | 4 |

Country mapping returned **HTTP 500**, matching its source's missing-configuration
behavior; it is excluded. B2B POST is excluded for state changes/executable input,
unverified bearer workflow and C1 base-path mismatch; it was not invoked.
The remaining four GETs returned JSON/200, but shared tool access and an enforceable
API scope have not been demonstrated. They are candidates, never confirmed coverage.
No operation counts are invented for DVWS or SREBench.

## 8. Authentication and sessions

Only anonymous benign inputs were exercised. The official B2B API declares bearer
authentication and source middleware enforces authorization. The login source is
captured for future review, but login/token acquisition, authenticated roles,
session expiry, CSRF requirements and test accounts were not exercised or verified.
There are no stored real credentials/tokens/cookies in deliverables. The example
configuration lists environment names only. Original DVWS and the unapproved
successor have version-specific auth/storage dependencies that remain unverified.

## 9. Repeatability and state

Plan: use a fresh uniquely named isolated digest-pinned instance for every
independent run, record identity/version and initial state, and retain evidence.
Juice Shop has DB/in-memory/challenge state; even GET challenge detection can affect
state for exploit-shaped inputs. Only reviewed `q=apple` and review ID `1` were used.
No account creation, state reset or snapshot restore was performed. Repeatable
clean-state equivalence remains unverified and is explicitly recorded, as permitted
by the eligibility checklist. Do not reuse the existing smoke target as clean data.
No destructive cleanup/reset commands are provided or executed in this phase.

## 10. Remaining blockers in priority order

1. Design and verify shared access to a fresh isolated target without exposing it
   publicly or changing existing containers. Current internal-only deployment has
   no effective host publication. Review an ingress/gateway network design first.
2. Prepare a separate concrete API-level allowlist, gateway isolation and bounds,
   using only reviewed candidates; preserve the approved root-only smoke manifest.
   No new scan may run without explicit approval.
3. Expand source-derived schemas carefully if broader research scope is desired;
   resolve C1 base-path/body/security/ID limitations separately before including
   affected operations. Do not silently transform away parser failures.
4. Resolve the original DVWS citation, or approve and document a DVWS-Node
   substitution with pinned build dependencies, reviewed deployment and spec.
5. Obtain SREBench runnable assets from its authors or separately authorize an
   implementation project. Scenario prose alone is not a deployable target.
6. Verify auth and independent state initialization before any authenticated or
   stateful comparison; then adjudicate ground truth in Phase 5.

## 11. Verification results and manual actions

**Passed:** 36 new benchmark unit/artifact tests; 72 unchanged baseline safety
tests; 4 existing C1 graph/tag/drift regressions. C1 emits one upstream FastAPI/httpx
deprecation warning. Both real spec schema validations and offline parser checks
passed. Exact regression argv, stdout, stderr and exit codes are preserved in
`specs/validation/regressions.json`.

**Actual failures, preserved:** runtime host-port publication check; expected
country-mapping HTTP 500; raw template-vs-example comparison before explicit
mapping. Harness setup failures (missing offline log directory, wrong Node PATH,
Windows language-response decoding) were corrected without touching components.
The decoding failure occurred after two benign GETs; the final completed route
check made five. Thus this script made seven benign target GETs across those two
attempts, not seven scans. No active/crawl requests occurred.

**Not executed / blocked:** end-to-end tool access to the isolated target, bearer
auth, clean-state reset/restore, original DVWS runtime/imports, DVWS-Node runtime
or imports, SREBench execution, full research benchmarks, ground-truth adjudication.
Existing C1 tests that require absent historical external datasets were not run;
no fixtures were fabricated to make them pass. Tests requiring live PenAgent
services or external model APIs were not run.

Preservation check: **134 existing files**, including **27 previous smoke files**,
all hashes unchanged and none missing. Both original and new container IDs, image
IDs, running states and application versions passed read-only checks. Existing
baseline configs, approved manifest and deadline/gateway/scan policy are unchanged.
No existing containers were deleted/reset, no Components 1–4 changed, and no
commits/pushes occurred. Only the prepared target and ephemeral offline test
containers were created. No private credentials were created or exported.

PowerShell verification commands and creation commands are in [COMMANDS.md](COMMANDS.md).
Manual decisions: identify the original DVWS URL or approve the named successor;
provide SREBench executable assets; review the proposed shared-access/scope design
before a new API experiment. There is no full benchmark approval pending implicitly.

## 12. Phase 5 handoff and stopping point

Candidate ground-truth sources: version-pinned Juice Shop challenge definitions,
source/tests and official companion guide; original DVWS exercise source and
README; DVWS-Node challenge guide/tests only if substitution is approved; provided
SREBench scenario descriptions only after a real implementation exists. These
are leads, not verified TP/FP/FN labels or comparable vulnerability counts.

Phase 5 would require independent mapping of seeded flaws to eligible operations,
reachability/prerequisite confirmation, reproducible state, and an adjudicated
reference independent of either tool's output. It has **not** started. No new
active scan, three-repeat benchmark or research result generation is authorized
by these preparation artifacts. Stop after this report.
