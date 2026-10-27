# Evidence, matching and metric contracts

All raw exports and generated results stay under ignored `local/` or `results/`.
The common schema is [findings.schema.json](../schemas/findings.schema.json).
Raw JSON/XML is read unchanged and identified by byte SHA-256. ZAP packaged JSON
uses `site[].alerts[].instances[]`; XML uses `OWASPZAPReport/site/alerts/alertitem`.
Malformed/missing files fail loudly, rather than becoming zero findings.

## Normalization and confidentiality

Each normalized record has tool/target, method/path, class, affected parameter/object,
risk/confidence, plugin/CWE/WASC identifiers when available and evidence references.
Scanner alert name, evidence, description, solution and instances remain available
through raw report references. Normalized `name` is a generic safe label, not the
original alert title. Request query values, evidence strings, response bodies,
credentials and free-text descriptions are not copied into publishable fields.
Original raw files still contain sensitive content; keep them private. Path
segments and parameter names can themselves carry sensitive data: ignore rules
and human review are essential, and no universal credential scrubber is claimed.

ZAP risk 0/1/2/3 becomes informational/low/medium/high. Confidence 0/1/2/3/4
becomes false_positive/low/medium/high/confirmed. Missing values stay null; unknown
codes are labeled unknown, never inferred. Scanner confidence "confirmed" does
not set `independently_verified`. No scanner alert is automatically ground truth.

Positive CWE numbers map directly to `CWE-<number>`; absent/zero/non-numeric values
are UNMAPPED. Broad OWASP categories, issue titles, signals and HTTP status codes
never invent a CWE. URL path case, slash and literal IDs are preserved; query and
fragment are removed. Missing methods/parameters/objects stay null.

Deduplication groups by target, tool, literal endpoint, method, CWE/class, plugin,
affected parameter/object. Every report instance is retained in `occurrences` and
raw references; repeated instances are not separately scored as vulnerabilities.
Different plugins/parameters or object paths remain separate candidates. Root-cause
grouping is an explicit later adjudication step. Representative risk/confidence
come from the first occurrence in the preserved export; all observations remain
in occurrences. IDs are deterministic for these keys; cross-tool IDs need not match.

`collect` can label plugins `active_rule`/`passive_rule` only when the actual run's
installed rule inventory was captured. That identifies rule type, not proof of
independent exploit verification or a particular message's initiator. Missing or
ambiguous provenance remains unknown. Packaged API scans also enable passive and
HTTP error/content scripts; do not call every resulting alert an active discovery.

The gateway can itself create denied/error responses and change transport/header
behavior. Preserve denied traffic and attribute each candidate to real forwarded
target evidence before interpreting it as a target issue. Gateway artifacts must
be rejected during adjudication. A narrow guard changes scan capabilities and
can prevent traversal/path mutation or crawling: document this reduced condition.

## Actual PenAgent adapter

Use the C3 public `GET /v1/audits/{audit}/evidence` response and C1
`GET /v1/graph/{target_id}`. The audit target field is **`audit.target`** (SQLite
public audit shape), not a fabricated `audit.target_id`. Join `result.op` to
`nodes[].id`; only `result.status=executed` plus recorded
`CONFIRMED_VULNERABILITY` interpretations are included. Preserve operation/probe
references and numeric C4 confidence. C4's operator security predicates provide
tool-level confirmation; independent benchmark verification still requires
adjudication. STRONG_SIGNAL, WEAK_SIGNAL, ERROR_CRASH and HTTP 200 alone do not
become findings. CWE/parameter/object are not inferred. The original exports are
never altered. Sources are hashed by the CLI.

## Reviewed comparison sidecars

To map literal paths to known OpenAPI templates or add supported vulnerability
class/parameter/object identities, use a **separate** sidecar per tool:

```json
{
  "source_sha256": "exact normalized-file byte hash",
  "reviewer": "reviewer identifier",
  "findings": {
    "actual finding ID": {
      "evidence_refs": ["private verified evidence reference"],
      "rationale": "Why this is the same operation and defect",
      "fields": {"category": "CWE-89", "endpoint": "/items/{id}",
                 "method": "GET", "parameter": "id", "verified_defect_id": "expert-defect-id"}
    }
  }
}
```

Only these comparison fields (plus `object`) may be enriched. Source scanner
classifications/evidence remain unchanged. Reviewers may assign a shared verified
defect ID only after inspecting evidence, not merely because titles resemble each
other. Hash/reviewer/evidence/rationale are mandatory. Output provenance records
both input and sidecar hashes.

Candidate pairs require equal target, exact mapped endpoint and mapped CWE. Known
method/parameter/object conflicts reject a pair. Unknown fields make matching
tentative. Shared verified pairs require matching known method and explicit shared
expert defect ID. Lists may contain multiple pairs for one root cause: pair counts
are not counts of unique vulnerabilities. Unmatched findings are only candidates;
unknown taxonomy and incomplete evidence can hide matches. Verified unique sets
come only from explicit expert defect IDs, otherwise N/A.

## Metrics

Observation fields use null for uncollected values; computed metrics use `N/A`.
Alert counts may be zero after a real empty report; missing exports never imply
zero. Coverage requires a complete traffic source and observed method/path set,
not imported OpenAPI paths, discovered URLs or alert locations. The gateway logs
actual eligible operations forwarded and their response status. Coverage counts
eligible **method/path operations**, and methods exercised lists distinct verbs.
Network errors can leave delivery uncertain; attempted upstream request count is
recorded separately from successful operation evidence.

`collect` uses actual total orchestration wall time (including network setup,
ZAP startup, crawl, audit and reporting) and gateway attempted upstream requests.
Denied requests are separate and are not target requests. No equivalence with
ZAP's message counter is assumed. Save the count definition; apply the same
definition/phases to PenAgent or report the confound. Resource limits are not
observed CPU/RAM usage; resource usage remains N/A unless measured independently.

Detection scoring requires a complete version-specific eligible universe and
reviewed labels for every finding:

```json
{
  "verified": true,
  "complete_eligible_universe": true,
  "source": "versioned authoritative ground truth and scope record",
  "reviewer": "expert identifier",
  "target_version": "deployed version",
  "vulnerability_ids": ["eligible-v1"],
  "labels": {
    "actual true-positive finding ID": {"verdict": "true_positive", "vulnerability_id": "eligible-v1", "evidence_refs": ["verified evidence"]},
    "actual rejected finding ID": {"verdict": "false_positive", "adjudicated_defect_id": "rejected-root-cause-1", "evidence_refs": ["review record"]}
  }
}
```

This is a format illustration, not a fabricated benchmark dataset. Ground truth
does not go into scanner/planner inputs. TP counts unique matched eligible IDs;
FP counts unique rejected root-cause IDs; FN counts unmatched eligible IDs.
Precision=TP/(TP+FP), recall=TP/(TP+FN), F1=2TP/(2TP+FP+FN). Zero denominators
are N/A. The proposal's FPR is emitted as `false_discovery_proportion` =
FP/(TP+FP). Statistical FP/(FP+TN) stays N/A because no TN universe is supplied.
Missing/incomplete/unverified annotations cannot enable detection scores.

Alerts/minute uses normalized alert candidates; verified findings/minute uses
adjudicated unique TP. Optional per-finding times, measured from the same start
event, enable time to first verified finding only after truth adjudication. Chain
depth/CVSS accuracy/action relevance/replanning require additional annotations
and are not inferred by this baseline.

Three-run aggregation requires completed statuses, repeat IDs 1-3, equal tool,
scan mode, request-count definition and condition fingerprint, and three distinct
reset-record references. The fingerprint includes target version/digest, original
spec hash, operation set, exclusions, auth role/mode, budgets, policy/rules, crawl,
scanner version/image, PenAgent commit and truth version. Reference strings alone
do not prove equivalent database state: preserve reset and initial-state evidence.
Full-web and API conditions cannot pool. For available numeric metrics output
mean and **sample** standard deviation (n-1 denominator); unavailable values stay
N/A. Failed/interrupted runs remain in the record and must be discussed, not hidden.
