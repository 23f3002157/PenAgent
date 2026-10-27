# Original API assets remain missing

No benchmark specification is fabricated or checked in. C1 candidates are
`specs/juice_shop_sample.json`, `specs/dvws_openapi.json` and
`specs/srebench_openapi.json`. None exist here. Juice Shop's documented live
candidate returned HTML, so no API-only scan readiness is claimed.

Preserve actual source bytes under ignored `original/`; save filtered copies under
ignored `prepared/`. The preparer supports JSON OpenAPI 3.0/3.1, one absolute
server and internal references. It checks information, methods, parameter locations,
path required flags, body content, responses and references. It is not a complete
OpenAPI conformance validator. Perform full version-appropriate OAS validation and
prove that the spec belongs to the deployed target before setting provenance flags.
YAML/Swagger 2 need explicitly reviewed conversion/bundling; do not silently change
schemas or fabricate endpoints. Preserve original and converted hashes.

Allowed operations include the source server's base path, e.g. `GET /v1/items`.
Preparation retains schemas/security/parameters/bodies, replaces only the server
origin with the scope gateway and filters the operation set. Preflight recreates
that transformation and rejects any semantic difference. Original/prepared byte
SHA-256 values differ from C1's canonical JSON hash and have distinct meanings.

URL input is fetched once from the approved host origin with no redirects and a
size limit, preserved unchanged, validated structurally and pinned locally before
ZAP import. This provides URL-based source support without allowing the scanner
to fetch an unreviewed remote definition during a timed active experiment.
