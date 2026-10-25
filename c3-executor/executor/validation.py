import re
from urllib.parse import quote, urlencode

from jsonschema import Draft7Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from penagent_common.models import Binding, HTTPArguments, StateWrite
from penagent_common.policy import Rejected, enforce_operation, enforce_url


def validate_schema(value, schema):
    # Never retrieve external $refs or silently accept a truncated SIS schema.
    def refs(v):
        if isinstance(v, dict):
            if "$ref" in v or any(str(v.get("description", "")).startswith(s) for s in ("Unresolved ref:", "External ref:", "Cyclic ref")):
                raise Rejected("unresolved_schema")
            for child in v.values():
                refs(child)
        elif isinstance(v, list):
            for child in v:
                refs(child)
    refs(schema)
    try:
        Draft7Validator.check_schema(schema)
        errors = list(Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(value))
        if errors:
            raise Rejected("request_schema_violation")
    except SchemaError:
        raise Rejected("invalid_endpoint_schema") from None


def resolve(value, state):
    if isinstance(value, dict):
        if set(value) == {"$state"}:
            ref = value["$state"]
            if not isinstance(ref, str) or not ref.startswith("object_ids."):
                raise Rejected("invalid_state_reference")
            key = ref[len("object_ids."):]
            if key not in state.values["object_ids"]:
                raise Rejected("missing_session_context")
            return state.values["object_ids"][key]
        return {k: resolve(v, state) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve(v, state) for v in value]
    return value


def build_arguments(probe, hypothesis, graph, target, state):
    nodes = {n.id: n for n in graph.nodes}
    if hypothesis.id != probe.hypothesis_id or not hypothesis.attack_sequence or not hypothesis.target_endpoints:
        raise Rejected("invalid_hypothesis")
    if any(op not in nodes for op in hypothesis.target_endpoints) or any(s.op not in nodes for s in hypothesis.attack_sequence):
        raise Rejected("hallucinated_endpoint")
    if probe.op not in {s.op for s in hypothesis.attack_sequence}:
        raise Rejected("probe_outside_hypothesis")
    steps = [s.step for s in hypothesis.attack_sequence]
    if steps != sorted(set(steps)) or any(s < 1 for s in steps):
        raise Rejected("invalid_step_order")
    node = nodes[probe.op]
    rule = target.operations.get(node.id)
    enforce_operation(node, rule, hypothesis.requires_approval)
    binding = Binding.model_validate(resolve(probe.binding.model_dump(), state))
    def destination_values(value):
        if isinstance(value, str) and value.lower().startswith(("http://", "https://", "file://", "gopher://", "ftp://")):
            enforce_url(value, target)
        elif isinstance(value, dict):
            for child in value.values():
                destination_values(child)
        elif isinstance(value, list):
            for child in value:
                destination_values(child)
    destination_values(binding.model_dump())
    def payload_risk(value):
        if isinstance(value, dict):
            for name, child in value.items():
                if name.lower() in {"role", "is_admin", "privileges", "balance", "amount", "credit_delta", "billing_tier", "account_status"}:
                    raise Rejected("approval_required_component5_unavailable")
                payload_risk(child)
        elif isinstance(value, list):
            for child in value:
                payload_risk(child)
        elif isinstance(value, str) and re.search(r"\b(delete|purge|truncate|withdraw|shutdown|reset|destroy|payment|purchase)\b", value, re.I):
            raise Rejected("approval_required_component5_unavailable")
    payload_risk(binding.query)
    payload_risk(binding.body)
    headers = binding.headers.copy()
    if any(k.lower() not in {h.lower() for h in rule.allowed_headers} for k in headers):
        raise Rejected("header_not_authorized")
    declared = {(p.location, p.name): p for p in node.parameters}
    for location in ("path", "query"):
        values = getattr(binding, location)
        if any((location, name) not in declared for name in values):
            raise Rejected("unknown_parameter")
    path = node.path
    for p in node.parameters:
        values = {"path": binding.path, "query": binding.query, "header": headers}.get(p.location, {})
        if p.required and p.name not in values:
            raise Rejected("missing_required_parameter")
        if p.name in values:
            value = values[p.name]
            validate_schema(value, p.schema_raw or {"type": p.schema_type or "string"})
            if p.location == "path":
                if str(value) in {".", ".."} or any(c in str(value) for c in ("/", "\\", "%", "?", "#")):
                    raise Rejected("unsafe_path_parameter")
                path = path.replace("{" + p.name + "}", quote(str(value), safe=""))
    if re.search(r"[{}]", path):
        raise Rejected("unresolved_path_parameter")
    if node.request_body_schema:
        # SIS currently loses requestBody.required and media type. Conservatively
        # require and validate a body whenever a body schema exists.
        validate_schema(binding.body, node.request_body_schema)
    elif binding.body is not None:
        raise Rejected("undocumented_request_body")
    args = HTTPArguments(method=node.method, url=target.base_url + path, headers=headers,
                         body=binding.body, body_type=binding.body_type, params=binding.query, session_ref=binding.session_ref)
    enforce_url(args.url, target)
    if args.session_ref and args.session_ref not in target.credential_refs:
        raise Rejected("session_reference_not_authorized")
    return node, rule, args
