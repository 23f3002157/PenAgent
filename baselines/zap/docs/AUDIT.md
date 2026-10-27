# ZAP baseline audit - 2026-10-25

Base commit: `fa6f8872622d60844027d3693572af44daf1c310`; initial working tree
clean. The Burp baseline directory is absent. This implementation starts from
scratch and changes no Component 1-4 source. No applicable AGENTS.md was found.

The 18-page research proposal at
`C:\Users\Kushi KKS\Downloads\PenAgent_Research_Paper.pdf` was reread, especially
Section 6 (pages 12-13) and the three-repetition requirement on page 16. It names
Juice Shop, DVWS and SREBench and lists both Burp Pro active scan and ZAP full active
scan as baselines. The operator now substitutes ZAP for the unavailable Burp Pro
condition. An API-focused ZAP condition differs from the proposal's full web scan;
these must be reported separately, never silently pooled. The proposal specifies
no fixed scanner version, policy, time budget or request cap. Those choices are
protocol decisions to freeze before experimentation. No scanner superiority is
assumed. Its FPR description is false discovery proportion, not FP/(FP+TN).

Inspected root README/Compose, images README, existing audit/compliance docs, C1
adapters/config/models, C3 public evidence routes/models and C4 classification
contracts. C1 ingests JSON/YAML OpenAPI 3.x and Swagger 2; nodes contain IDs,
method/path, parameters, request/response schemas and auth. C3 evidence exports
audit/probes/transitions, with result.op joined to C1 node.id; C4 classifies
CONFIRMED_VULNERABILITY, STRONG_SIGNAL, WEAK_SIGNAL, NEGATIVE and ERROR_CRASH.
Only recorded confirmed interpretations can be included as tool-confirmed findings;
benchmark verification is a separate adjudication step.

## Actual environment

- Docker Desktop 4.73.1; Linux Engine/client 29.4.3; Compose 5.1.3. Engine is healthy
  outside sandbox. Initial sandbox inspection was denied by named-pipe permissions.
- Existing Juice Shop `blissful_chebyshev`, container
  `0356c18439557ca2fed64e8c69f73035c4b485ca069b6f961b1de038f17d9ac3`, running.
  Version **20.0.0**, read from `/juice-shop/package.json` with its own Node runtime.
  Existing mapping is host all-interfaces port 3000 -> container 3000. It was
  preserved, not recreated. Container IP 172.17.0.2 on bridge is an observation,
  not a permanent endpoint. Host-facing address is `http://127.0.0.1:3000`.
- Juice image digest:
  `bkimminich/juice-shop@sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f`.
- Official scanner image was already installed; no pull was necessary:
  `ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6`.
  `zap.sh -version` reports **2.17.0**. API/full scanner help read directly inside
  network-disabled containers. API `-S` skips active scanning and is forbidden.
  `-T` limits startup/passive wait, not total active scan time.
- Harmless GET `/` from the scanner image on Docker bridge to
  `http://host.docker.internal:3000/` returned HTTP 200, HTML. This is connectivity
  evidence only, not an active scan or vulnerability discovery.
- C1-C4 and their internal synthetic fixture are running. They are excluded from
  all research scans, especially ports 9001-9004 and fixture port 9010.

## Available assets and blockers

The only currently observed research target is Juice Shop. No DVWS/SREBench
containers/images were listed. Their unified image and ports 18001-18003 are
documented in `images/README.md`, not verified deployments. Root Compose runs the
PenAgent services and fixture, not the benchmark suite. The README's external
testbed Compose path and illustrative `penagent.cli` command are absent here.

No `specs/juice_shop_sample.json`, `dvws_openapi.json`, `srebench_openapi.json`,
`datasets/ground_truth_chains.json` or executable benchmark evaluation harness was
found. C1 has candidate live URLs, not authoritative checked-in specifications.
The available `images/SREBench API.pdf` is a design reference; the previous audit
documents its topology differences and missing executable assets. No definitions
or machine-readable ground truth are invented from its scenario descriptions.

Juice Shop root accessibility is not proof that the candidate OpenAPI route is a
valid target-version definition. API-only readiness requires obtaining the exact
C1 source and validating its provenance. A narrow separately labeled full-web
smoke protocol can be prepared from observed GET `/`, but it does not establish
full benchmark coverage. No authenticated test account is currently verified.
Equivalent fresh state/reset records and version-specific eligible ground truth
remain necessary for the three-repeat comparative experiment.

Safety design: packaged scanner plus reviewed context/policy and a method/path
allowlist gateway. An isolated scanner network and runtime egress checks must
verify that the gateway cannot be bypassed. The gateway preserves forwarded
requests but records denials, pacing, budget and actual traffic. This constrains
attack coverage and must be reported. Policy and runtime checks are fail-closed.
No real active scan may run until explicit operator confirmation for the concrete
manifest/configuration is recorded. Unit tests and harmless connectivity checks
do not satisfy scan execution.
