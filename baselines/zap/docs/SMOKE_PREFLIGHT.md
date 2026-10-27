# Approved smoke test stopped before execution - 2026-10-25

The operator explicitly approved exactly one GET `/` smoke scan, conditional on
gateway limits, network isolation, a 180-second runner deadline and unchanged
target identity all being verified. **No scan was launched** because the deadline
verification failed. No real approval file was consumed and no scan was retried.

The approved manifest, implementation hash and generated gateway/common/hooks
bundle still matched the reviewed dry-run. Juice Shop remained running with the
same approved full container ID and immutable image digest. TCP-only probes on
the internal scanner network could not reach the target via
`host.docker.internal:3000`, `172.17.0.2:3000`, or the Docker-host gateway
`172.20.0.1:3000`; no HTTP application data was sent. The IPv4 route table contained
only the internal subnet route, with no default route.

The exact unchanged generated gateway was tested with a mocked upstream: all five
disallowed method/URL cases returned 403; 100 GET `/` requests were accepted; the
101st returned 403; the mocked upstream saw exactly 100 requests. This is a
synthetic preflight test, not experimental target traffic or ZAP findings.

A deterministic runner test mocked all Docker/ZAP execution and advanced the
setup clock to 181 seconds. The existing `runner.run` still called Popen and gave
the process a one-second wait, because it uses
`max(1, wall_seconds - elapsed)` without rejecting an exhausted budget before
launch. The timeout path also allows a five-second Docker stop grace. Consequently
the approved runner cannot establish the requested strict overall deadline.
No source/configuration/bundle was changed to bypass or repair this failed check.

Actual smoke-scan forwarded requests: **0**. Actual smoke-scan blocked requests:
**0**. Scan duration, alert severity totals, report imports and completion are
**N/A / not started**. No ZAP JSON/XML/HTML finding reports exist for this attempt;
none were fabricated. Existing historical unit/configuration validation does not
make this preflight pass.

Private evidence:

- `local/approved-smoke-preflight/constraint-verification.json`: explicit mock-test
  labeling, exact gateway boundary results and failing deadline trace.
- `local/approved-smoke-preflight/final-run-manifest.json`: unchanged approved
  configuration/hashes, verified target, zero actual scan activity and stop reason.
- `local/approved-smoke-preflight/network_probe.py` and `verify_constraints.py`:
  reproducible diagnostics, which do not launch real scans.

Execution status is **BLOCKED BY PREFLIGHT FAILURE**, superseding the earlier
ready-for-approval statement. A deadline correction and renewed verification are
required before any real scan. PenAgent components, the target container, approved
configuration and generated runtime bundle remain unchanged. Nothing was committed
or pushed.
