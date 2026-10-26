# Research paper compliance

The supplied paper's Sections 5.4–5.7 and Table 4 govern component numbering.
This map distinguishes implemented C3-C6 behavior from remaining open items.

| Requirement | Implementation | Executed verification |
|---|---|---|
| 5.4 http_request | executor/service.py, validation.py; HTTPArguments | test_executor valid_request, invalid_method, invalid_url, unauthorized_destination, unsafe_redirect, http_errors_are_responses, network_errors, retry_never_post, oversized_response |
| Strict structured tool calls | executor/tools.py; penagent_common/models.py | test_strict_tool_arguments; test_all_four_bound_tools_over_live_target |
| Parse response and extract state | executor/parser.py; response schemas from existing SIS models | test_parse_variants, schema_aware_credentials, secret_redaction |
| Read session knowledge | penagent_common/store.py; bound Tools | test_state_isolation_persistence_encryption; test_contracts_sessions_and_endpoints |
| Write knowledge for subsequent calls | encrypted category/key upserts; parser artifact extraction | same state/session tests; four-tools integration test |
| Execute actual C2 hypotheses | executor/workflow.py; existing AttackHypothesis model | test_live_closed_loop; test_contracts_sessions_and_endpoints |
| Resolve actual C1 operation graph | Executor.graph and build_arguments; existing EndpointGraph model | live ingestion/planning contract test; hallucinated_endpoint, schema_validation_blocks_remote_refs_and_bad_parameters |
| Explicit ordered dependencies, no guessed IDs | Binding.depends_on and $state object-ID references | live session-chain test, missing_context |
| Authorized targets and risk boundary | common/policy.py, operator config, Component 5 approval gate | invalid_url, unauthorized_destination, test_approval_denied_by_semantics, untrusted_body_cannot_extend_policy |
| 5.5 five Table 4 categories | interpreter/evidence.py | test_five_classifications parametrization and timeout_not_crash |
| Confirmed: exploit success in authorized context | operator-defined forbidden-value and protected-field predicates | replanning_trigger; actual simulated positive in live_closed_loop |
| Strong: suggestive, unconfirmed | evidence fields plus operator expectation | strong-signal case; valid_mutation_and_duplicate |
| Weak: unusual, insufficient proof | evidence preservation; no status-only confirmation | misleading HTTP 200 cases in five_classifications |
| Negative: clean rejection, no useful evidence | rejection with no configured protected/signal fields | HTTP 403 negative unit and live scenario |
| Error/crash: 5xx or execution error, halt | error category with distinct transport explanation, 5xx audit halt | HTTP 500/503 unit tests, timeout_not_crash |
| Adaptive mutation from actual response | interpreter/service.py; missing permitted header, field-specific schema boundary/enum, observed ID/session references | valid_mutation_and_duplicate, payload_and_auth_mutations (payload branch), no_progress_termination |
| Validate before executing follow-up | C3 repeats schema/policy/ancestry/budgets | invalid_mutation_parent, mutation_budget_exhausted; live C4→C3 follow-up |
| Evidence, concise explanation, next action | Interpretation strict model; hashed/redacted public evidence | five_classifications, live_closed_loop and saved reports/demo.json |
| Significant evidence → global planner | Workflow.handoff calls actual feedback and /events/replan | interpreter_restart_and_c4_recovery verifies done handoff records |
| Bounded probes, mutations, duration, LLM, concurrency | SQLite reservations/counters/leases/network slots | duplicate_and_budget, duration_and_chain_budget, atomic_probe_budget, cross_process_limiter, llm_budget |
| Cancellation and safe resumability | SQLite checkpoints and no replay of uncertain reservations | cancellation_during_stream, unknown_outcome_never_replayed, interpreter_restart_and_c4_recovery |
| LLM/provider separation and validation | interpreter/provider.py, gemini.py; native structured output; model cannot authorize/promote confirmation | test_gemini.py; live demo.gemini_check and demo.gemini_application |
| Model-selected mutation is actually applied | interpreter/service.py recommendation_allowed/recommendation_matches | model choice tests for header, parameter, body, auth and state; malformed output, timeout and provider failures |
| Independent mutation branches | interpreter/service.py | test_mutation_branches.py: parameter boundaries, auth context, observed ID reuse, depth and no-progress checks |
| Confirmed stop retains planner handoff | executor/workflow.py | test_confirmed_stop_still_records_planner_handoff |
| Legacy resource compatibility | sis/storage.py, hgs/queue.py | test_legacy_connections.py; 6 C1 and 8 C2 available regressions |
| 5.6 Human gate pauses non-safe actions | executor/service.py (reserve+request_approval), penagent_common/store.py approvals table | test_approvals.py: test_destructive_op_becomes_pending |
| 5.6 Operator approve/deny/timeout decision | executor/main.py approvals routes, Store.decide_approval, _expire_approvals | test_approve_executes_for_real, test_deny_blocks_permanently, test_timeout_auto_skips, test_approvals_http_endpoints |
| 5.6 Approval bypass scoped to one probe, not promotable by a model | validation.build_arguments(approved=...), policy.enforce_operation(approved=...) | test_approved_bypass_scoped_to_one_probe, test_double_decide_rejected, test_approve_rejects_wrong_probe_state |
| 5.6 Budget interplay with pending approvals | Store.reserve reused for pending probes | test_budget_exhaustion_not_mistaken_for_approval |
| 5.7 CVSS-scored, reproducible findings | c6-report/report/synth.py, cvss.py (deterministic FIRST.org formula, never LLM-assigned) | test_report.py: test_confirmed_finding_chain_and_cvss, test_cvss_reference_vectors |
| 5.7 Findings/observations/operational-issues buckets by classification | report/synth.py build_report | test_report_buckets_each_classification |
| 5.7 Remediation and report API | report/synth.py remediation lookup; report/main.py GET /v1/audits/{audit}/report | test_remediation_lookup_hits_known_category_and_falls_back, test_report_http_endpoint |
| 6.2 TPR/FPR/chain-depth/CVSS-accuracy/time-to-finding/unnecessary-action/replan-frequency metrics | demo/evaluate.py (real implementation; the container's own evaluate.py is non-functional) | tests/test_evaluate.py (7 cases); real run in docs/RESULTS.md |
| 6.1 Datasets and targets: Juice Shop, DVWS, SREBench-API | demo/run_evaluation.py, demo/eval_targets.py against the real monisha117/penagent-target-env container | docs/RESULTS.md; reports/eval-autonomous.json, reports/eval-guided.json |
| 6.4 Ablation-adjacent: autonomous vs. guided execution modes | demo/run_evaluation.py's two modes, never conflated | docs/RESULTS.md's per-target, per-mode tables |
| 6.3 PentestGPT baseline (prompt-only, no execution) | demo/baseline_pentestgpt.py; Ollama open models in place of GPT-4, stated explicitly | docs/RESULTS.md's baseline section; same demo/evaluate.py scoring as PenAgent's own runs |

## Explicit boundaries and unverified areas

- No existing LangGraph runtime/checkpointer existed. This adds a durable minimal
  orchestration seam, not a complete LangGraph application.
- Component 5 lives inside C3 as a control-flow gate, not a separate network
  service -- it was not deployed as its own Table 3 "component" process.
  Resuming a hypothesis chain automatically after an approval is not implemented;
  the operator decides how to continue manually, matching how this codebase
  already refuses to auto-replay other interrupted/uncertain outcomes.
- Component 6's CVSS v3.1 scoring is deterministic from operator-configured
  policy fields (OperationPolicy.risk, Expectation.protected_fields) and probe
  mutation depth, not derived from response content or an LLM. Scope is fixed
  at Unchanged (S:U) and availability impact at None (A:N) as documented
  conservative defaults; this is not a claim of exhaustive CVSS fidelity.
- Mutation strategies have deterministic policy validation and independent tests
  for header, body, parameter boundaries, auth context and observed ID reuse.
  Combined statement/branch interpreter coverage is 88%, not exhaustive coverage.
- Numeric-IP targeting, explicit cookie strings, conservative body requirements,
  target-scoped HGS queues and unknown-outcome review are documented constraints.
- Historical regressions cannot all pass without missing authoritative specs and
  datasets. Docker availability does not replace missing inputs. No benchmarks
  were created; fixture results do not replace those historical results.
- Real Gemini calls and Docker/Python 3.11 execution were independently exercised.
  The positive fixture is simulated; no real-world vulnerability is claimed.
- Section 6's evaluation (docs/RESULTS.md) does not include the paper's 6.3
  baseline comparisons (Burp Suite Pro, OWASP ZAP, PentestGPT) -- explicitly
  deferred. It is n=1 per (target, mode), not the paper's 3-run mean/stdev.
  Autonomous-mode discovery scored 0% TPR on all three real targets, traced
  to a specific, documented limitation in C4's mutation-discovery (keyed off
  literal JSON fields the synthetic fixture uses, not present in real
  targets' responses) -- guided-mode results (up to 100% TPR) show the
  execution/classification/approval/report pipeline itself is correct once
  pointed at a real attack path.
