# Phase 4 benchmark preparation

Preparation is complete to the extent supported by authentic assets. No target is
currently ready for an API-level experiment. Read [PHASE4_READINESS.md](docs/PHASE4_READINESS.md)
and [COMMANDS.md](docs/COMMANDS.md) before using these artifacts. Nothing here grants
scan authorization. The existing root-only smoke configuration/evidence is unchanged.

All changes in this phase are new files under `benchmarks/`. `local/` is ignored;
it contains downloaded candidate material, installed validation dependencies and
offline ZAP daemon files, not benchmark results or verified vulnerability labels.
`sources/juice-shop-20.0.0/` contains MIT source excerpts with the upstream LICENSE.
Synthetic test cases are confined to tests and explicitly labeled parser cases.

Run from the repository root, using a Python with the validation dependencies:

```powershell
python -B -m benchmarks validate-spec benchmarks/specs/prepared/juice-shop-20.0.0-readonly-host.json --full
python -B -m benchmarks validate-manifest benchmarks/manifests/juice-shop-20.0.0.json
python -B -m benchmarks readiness --out benchmarks/local/readiness-check.json
python -B -m benchmarks audit --out benchmarks/local/prerequisite-check.json
python -B -m unittest discover -s benchmarks/tests -v
```

`requirements-validation.txt` pins the direct validation dependencies. The actual
environment lock is in `specs/validation/dependencies.json`. Runtime uses the
existing digest-pinned image; no image was pulled or rebuilt. Public C1 classes
were exercised offline, without changing any component or writing a service DB.

Artifact generation is deterministic and append-only: an identical JSON artifact
is accepted; differing evidence is never overwritten. Live/import scripts refuse
an existing evidence output. They are **not** general-purpose benchmark runners.
Do not rerun live checks automatically. `build_readiness` consumes the saved
evidence, and `generate_specs` consumes captured source; neither contacts targets.

The manifest contract is enforced by `core.validate_manifest`, with exact fields,
an exact 12-boolean checklist, version/digest/hash checks and readiness consistency.
Inventory schema version 1 uses `(method, public normalized path)` for operation
identity and stable SHA-256-derived IDs. Missing target inventories use `operations:
null`, never invented zero operation counts. Concrete ZAP path examples are mapped
to exactly one declared template while preserving the original capture evidence.

No credentials, account creation or authenticated execution are needed for the
reviewed subset. `config/credentials.example.json` lists environment names only.
Do not treat the unverified B2B role/session requirements as supported workflows.
