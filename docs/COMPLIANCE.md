# Research paper compliance

The supplied paper's Sections 5.4–5.5 and Table 4 govern component numbering.
This map distinguishes implemented C3/C4 behavior from future system components.

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
| Authorized targets and risk boundary | common/policy.py, operator config, DenyApprovalGate | invalid_url, unauthorized_destination, approval_denied_by_semantics, untrusted_body_cannot_extend_policy |
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

## Explicit boundaries and unverified areas

- No existing LangGraph runtime/checkpointer existed. This adds a durable minimal
  orchestration seam, not a complete LangGraph application.
- Component 5 remains unavailable. Risky actions are denied, not approved through
  a pretend human gate. Component 6's CVSS/report synthesis is outside this work.
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
