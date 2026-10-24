from pydantic import ValidationError
from hgs.models import AttackHypothesis
from sis.models import EndpointGraph
from penagent_common.models import Category, ExecutionResult, Interpretation, Mutation, Probe
from penagent_common.policy import Rejected
from executor.validation import build_arguments
from interpreter.evidence import interpret, lookup
from interpreter.provider import create_provider, Recommendation
import asyncio
import time


class Interpreter:
    def __init__(self, settings, store, provider=None):
        self.settings, self.store = settings, store
        self.provider = provider or create_provider(settings)

    def context(self, audit, owner, probe_id):
        stored = self.store.get_probe(audit, owner, probe_id)
        if not stored["result"]:
            raise Rejected("probe_outcome_unknown_do_not_replay")
        result = ExecutionResult.model_validate(stored["result"])
        context = stored["context"]
        return stored, result, AttackHypothesis.model_validate(context["hypothesis"]), Probe.model_validate(context["probe"]), EndpointGraph.model_validate(context["graph"])

    async def interpret(self, audit, owner, probe_id):
        stored, result, hypothesis, probe, graph = self.context(audit, owner, probe_id)
        if stored["interpretation"]:
            return Interpretation.model_validate(stored["interpretation"])
        target = self.settings.targets[self.store.audit(audit, owner)["target"]]
        rule = target.operations.get(probe.op)
        output = interpret(result, hypothesis, probe, rule, self.store.trace(audit, owner)["probes"])
        # LLM recommendations may conservatively stop/preserve; classification
        # and confirmations always remain tied to deterministic evidence.
        enabled = self.settings.llm_provider != "none" or (self.settings.llm_url and output.next_action == "mutate")
        if enabled and result.status == "executed" and result.status_code < 500:
            try:
                self.store.llm_reserve(audit, owner)
                node = next(n for n in graph.nodes if n.id == probe.op)
                state = self.store.read(audit, owner, secrets=True)
                summary = model_summary(result, output, node, rule, state)
                remaining = self.store.audit(audit, owner)["created"] + self.settings.max_duration - time.time()
                async with asyncio.timeout(max(.001, min(self.settings.llm_timeout, remaining))):
                    suggestion = Recommendation.model_validate((await self.provider.recommend(summary)).model_dump())
                output.model_assessment = {"provider": self.settings.llm_provider, "model": self.settings.llm_model,
                    "classification": suggestion.classification, "schema_valid": True,
                    "action": suggestion.action, "strategy": suggestion.strategy,
                    "usage": getattr(self.provider, "last_usage", {})}
                if suggestion.action != "mutate":
                    output.next_action = suggestion.action
                elif output.classification in {Category.STRONG_SIGNAL, Category.WEAK_SIGNAL} and recommendation_allowed(suggestion, summary):
                    output.next_action = "mutate"
                    self.store.event(audit, "model_recommendation", {"probe_id": probe_id, "recommendation": suggestion.model_dump()})
                else:
                    output.next_action, output.error = "preserve", "llm_invalid_mutation"
            except Rejected as exc:
                output.next_action, output.error = "preserve", str(exc)
            except TimeoutError:
                output.next_action, output.error = "preserve", "llm_timeout"
            except (ValidationError, AttributeError, TypeError):
                output.next_action, output.error = "preserve", "llm_malformed_output"
        self.store.interpretation(audit, probe_id, output)
        return output

    async def mutate(self, audit, owner, probe_id) -> Mutation | None:
        stored, result, hypothesis, probe, graph = self.context(audit, owner, probe_id)
        interpretation = await self.interpret(audit, owner, probe_id)
        if interpretation.next_action != "mutate" or interpretation.classification not in {Category.STRONG_SIGNAL, Category.WEAK_SIGNAL}:
            return None
        self.store.active(audit, owner)
        trace = self.store.trace(audit, owner)["probes"]
        count = sum(bool(p["context"]["probe"]["parent_probe_id"]) for p in trace if p["context"]["probe"]["hypothesis_id"] == hypothesis.id)
        if count >= self.settings.max_mutations or probe.depth + 1 >= self.settings.max_depth:
            raise Rejected("mutation_budget_exhausted")
        target = self.settings.targets[self.store.audit(audit, owner)["target"]]
        rule = target.operations[probe.op]
        node = next(n for n in graph.nodes if n.id == probe.op)
        state = self.store.read(audit, owner, secrets=True)
        candidates = []
        # A response may name a missing declared header, but cannot invent the
        # allowed value or extend the operator's header policy.
        missing = lookup(result.parsed.data, "missing_header") if result.parsed else None
        if isinstance(missing, str) and missing in rule.header_variations:
            for value in rule.header_variations[missing]:
                binding = probe.binding.model_copy(deep=True)
                binding.headers[missing] = value
                candidates.append((binding, f"response named missing permitted header {missing}"))
        # Boundary tests only after a field-specific validation error in the
        # observed response, using boundaries from the graph schema.
        field = lookup(result.parsed.data, "invalid_parameter") if result.parsed else None
        if isinstance(field, str):
            for parameter in node.parameters:
                if parameter.name == field and parameter.location == "query":
                    for key in ("minimum", "maximum"):
                        if key in parameter.schema_raw:
                            binding = probe.binding.model_copy(deep=True)
                            binding.query[field] = parameter.schema_raw[key]
                            candidates.append((binding, f"observed validation error for {field}; test schema {key}"))
            # Payload alternatives are derived from this endpoint's schema and
            # an observed field-specific error, never from a replay payload list.
            definition = (node.request_body_schema or {}).get("properties", {}).get(field)
            if definition and isinstance(probe.binding.body, dict):
                values = list(definition.get("enum", []))
                values.extend(definition[k] for k in ("minimum", "maximum", "default") if k in definition)
                for value in values:
                    binding = probe.binding.model_copy(deep=True)
                    binding.body[field] = value
                    candidates.append((binding, f"observed payload validation error for {field}; use schema-valid alternative"))
        compare = lookup(result.parsed.data, "compare_auth_context") if result.parsed else None
        if compare is True:
            for ref in rule.auth_context_variations:
                if ref in target.credential_refs and (ref in state.values["tokens"] or ref in state.values["cookies"]):
                    binding = probe.binding.model_copy(deep=True)
                    binding.session_ref = ref
                    candidates.append((binding, "observed context discrepancy; compare an operator-approved existing session"))
        # Reuse only an observed identifier when the API explicitly reports a
        # missing parameter; no guessed alternate users or credentials.
        missing_param = lookup(result.parsed.data, "missing_parameter") if result.parsed else None
        if isinstance(missing_param, str):
            for key in state.values["object_ids"]:
                if key.endswith("." + missing_param):
                    for parameter in node.parameters:
                        if parameter.name == missing_param and parameter.location in {"query", "path"}:
                            binding = probe.binding.model_copy(deep=True)
                            getattr(binding, parameter.location)[missing_param] = {"$state": "object_ids." + key}
                            candidates.append((binding, "observed missing identifier; reuse previously observed state"))
        import hashlib, json
        fingerprints = {p["result"]["request_fingerprint"] for p in trace if p["result"]}
        recommendations = [e["data"]["recommendation"] for e in self.store.trace(audit, owner)["events"]
                           if e["kind"] == "model_recommendation" and e["data"].get("probe_id") == probe_id]
        selected = Recommendation.model_validate(recommendations[-1]) if recommendations else None
        for binding, change in candidates:
            if selected and not recommendation_matches(selected, probe.binding, binding):
                continue
            candidate = Probe(hypothesis_id=hypothesis.id, op=probe.op, binding=binding, parent_probe_id=probe_id, depth=probe.depth + 1, motivation=change)
            try:
                _, _, args = build_arguments(candidate, hypothesis, graph, target, state)
            except (Rejected, ValidationError):
                continue
            fingerprint = hashlib.sha256(json.dumps(args.model_dump(mode="json"), sort_keys=True, allow_nan=False).encode()).hexdigest()
            if fingerprint in fingerprints:
                continue
            self.store.transition(audit, "MUTATING")
            return Mutation(original_hypothesis_id=hypothesis.id, observation_id=probe_id, change=change, probe=candidate)
        self.store.event(audit, "no_progress", {"probe_id": probe_id, "reason": "no_new_validated_mutation"})
        return None


def model_summary(result, output, node, rule, state):
    """Use schema names and boolean observations; never response free text/values."""
    data = result.parsed.data if result.parsed else None
    missing = lookup(data, "missing_header")
    invalid = lookup(data, "invalid_parameter")
    missing = missing if isinstance(missing, str) else None
    invalid = invalid if isinstance(invalid, str) else None
    missing_parameter = lookup(data, "missing_parameter")
    missing_parameter = missing_parameter if isinstance(missing_parameter, str) else None
    parameters = {p.name: [p.schema_raw[k] for k in ("minimum", "maximum") if k in p.schema_raw]
                  for p in node.parameters if p.location == "query"}
    bodies = {k: list(v.get("enum", [])) + [v[n] for n in ("minimum", "maximum", "default") if n in v]
              for k, v in (node.request_body_schema or {}).get("properties", {}).items()}
    # Only primitive schema choices are shared; nested arbitrary payloads are not.
    bodies = {k: [v for v in values if isinstance(v, (str, int, float, bool))] for k, values in bodies.items()}
    refs = [r for r in rule.auth_context_variations if r in state.values["tokens"] or r in state.values["cookies"]]
    expectation = rule.expectation
    return {"classification": output.classification.value, "status_code": result.status_code,
        "predicate_satisfied": output.classification == Category.CONFIRMED_VULNERABILITY,
        "allowed_headers": rule.header_variations, "allowed_parameters": parameters, "allowed_body_values": bodies, "allowed_sessions": refs,
        "observations": {"missing_header": missing if missing in rule.header_variations else None,
            "invalid_parameter": invalid if invalid in parameters or invalid in bodies else None,
            "compare_auth_context": lookup(data, "compare_auth_context") is True,
            "missing_parameter": missing_parameter if missing_parameter in parameters else None,
            "signal_fields_present": [p for p in expectation.signal_fields if lookup(data, p) is not None] if expectation else [],
            "protected_fields_present": [p for p in expectation.protected_fields if lookup(data, p) is not None] if expectation else []}}


def recommendation_allowed(suggestion, summary):
    observations = summary["observations"]
    strategy = suggestion.strategy or ("header" if suggestion.header_name else None)
    if strategy == "header":
        return suggestion.header_name == observations["missing_header"] and suggestion.header_value in summary["allowed_headers"].get(suggestion.header_name, [])
    if strategy in {"parameter", "body"}:
        options = summary["allowed_parameters" if strategy == "parameter" else "allowed_body_values"]
        return suggestion.parameter_name == observations["invalid_parameter"] and suggestion.parameter_value in options.get(suggestion.parameter_name, [])
    if strategy == "auth":
        return observations["compare_auth_context"] and suggestion.session_ref in summary["allowed_sessions"]
    if strategy == "state":
        return suggestion.parameter_name is not None and suggestion.parameter_name == observations["missing_parameter"]
    return False


def recommendation_matches(suggestion, original, binding):
    strategy = suggestion.strategy or ("header" if suggestion.header_name else None)
    if strategy == "header":
        return binding.headers.get(suggestion.header_name) == suggestion.header_value and binding.headers != original.headers
    if strategy == "parameter":
        return binding.query.get(suggestion.parameter_name) == suggestion.parameter_value and binding.query != original.query
    if strategy == "body":
        return isinstance(binding.body, dict) and binding.body.get(suggestion.parameter_name) == suggestion.parameter_value and binding.body != original.body
    if strategy == "auth":
        return binding.session_ref == suggestion.session_ref and binding.session_ref != original.session_ref
    if strategy == "state":
        return binding.query != original.query or binding.path != original.path
    return False
