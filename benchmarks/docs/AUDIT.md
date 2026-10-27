# Phase 4 initial audit - 2026-10-25

Repository HEAD: `fa6f8872622d60844027d3693572af44daf1c310`. Initial Git status:
`?? baselines/`; preserve the entire uncommitted ZAP baseline. No applicable
AGENTS.md exists in the checkout. New Phase 4 work is isolated under `benchmarks/`.

Inspected the repository file inventory, root and component READMEs, Compose and
Dockerfiles, SIS adapters/normalizer/models/graph builder/service/API, HGS models,
C3 validation/session/policy and public evidence contracts, C4 interpretation and
mutation service, historical regression fixtures, images documentation, existing
ZAP runner/config/schemas and its actual smoke/deadline reports. The supplied
18-page proposal's evaluation and references were reread. Its DVWS reference is
author/year/title only, with no repository URL or version. The operator explicitly
prioritizes the original project, not DVWS-Node.

## Existing reusable assets

- C1 parses JSON/YAML OpenAPI 3.x and Swagger 2, builds deterministic operation
  nodes and inferred dependency edges, and stores graphs in SQLite. Direct
  normalizer/graph-builder testing can avoid writing to the running service DB.
- C2 consumes graph nodes/operation IDs and ranked hypotheses. Proposed dependency
  edges and OWASP tags are heuristics, not benchmark ground truth.
- C3 binds graph operations to exact authorized method/path policies, numeric-IP
  origins and audit-scoped encrypted sessions/evidence. C4's recorded confirmed
  category depends on operator predicates; signals/HTTP 200 do not establish truth.
- The independent ZAP baseline uses pinned 2.17.0, a method/path guard, monotonic
  deadline and shared-operation policy. Its executed root-only smoke has immutable
  raw reports and run metadata. Reuse its conventions; do not repeat the scan.
- Existing root tests and demo fixture are synthetic tooling tests, not research
  targets. Root Compose runs C1-C4 plus that fixture, not DVWS or SREBench.

## Current deployment and missing assets

Docker Desktop Linux engine is running. Existing Juice Shop is 20.0.0, container
`blissful_chebyshev`, image digest
`bkimminich/juice-shop@sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f`,
published on host port 3000. Its existing all-interface binding is preserved.
New optional deployment definitions will use loopback only and a distinct name.
No DVWS, DVWS-Node or SREBench images/containers appeared in the current inventory.

No complete general Juice Shop spec, DVWS spec, SREBench spec or machine-readable
ground truth exists in this checkout. The expected historical `specs/` and
`datasets/` assets are absent. Images README's unified image is a third-party
documented claim, not verified executable provenance. Its nonexistent example
CLI and external Compose path cannot be used as deployment evidence.

## Newly discovered authoritative source

Juice Shop's v20.0.0 source includes an official **narrow B2B** OpenAPI 3.0 file:
https://github.com/juice-shop/juice-shop/blob/v20.0.0/swagger.yml

It describes POST `/orders` relative to `/b2b/v2`, with Bearer security. It is not
a complete specification for the application's other REST endpoints. That operation
is state-changing and will not be invoked in this phase. Preserve original bytes,
normalize only server addressing with provenance, and report C1 base-path/body
limitations rather than hiding them. A separate non-official read-only subset may
be derived from versioned deployed source and benign route observations.

## Non-attacking verification plan

Snapshot existing source/smoke hashes first. Read target source and version metadata,
validate real definitions, and use network-disabled C1 and ZAP parser containers.
ZAP OpenAPI import may send requests during example generation: any parser test
must have no network and use an inert local capture interface, not a live target.
Only a finite, explicitly reviewed list of benign read-only target GETs may be
used for live route verification. No login/account creation, mutation, crawler,
Full Scan, active scan, existing-container reset or component change is authorized.
