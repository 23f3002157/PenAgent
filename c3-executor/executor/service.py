import asyncio
import hashlib
import json
import logging
import time
from urllib.parse import urljoin
from uuid import uuid4

import httpx
from pydantic import ValidationError
from sis.models import EndpointGraph
from hgs.models import AttackHypothesis
from penagent_common.http import service_call
from penagent_common.models import ExecutionResult, HTTPArguments, Probe, StateWrite
from penagent_common.policy import Rejected, enforce_url, origin, redact
from executor.parser import parse_response
from executor.validation import build_arguments

logger = logging.getLogger(__name__)


class DenyApprovalGate:
    """Component 5 integration boundary. There is intentionally no approval API."""
    async def approve(self, **context) -> bool:
        return False


class Executor:
    def __init__(self, settings, store, transport=None):
        self.settings, self.store = settings, store
        self.transport = transport
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        self.rate_lock = asyncio.Lock()
        self.next_request = 0.0
        self.gate = DenyApprovalGate()

    async def graph(self, target: str, correlation: str) -> EndpointGraph:
        from urllib.parse import quote
        data = await service_call(self.settings, "GET", self.settings.sis_url, f"/v1/graph/{quote(target, safe='')}", correlation_id=correlation)
        try:
            graph = EndpointGraph.model_validate(data)
        except ValidationError:
            raise Rejected("upstream_graph_contract_violation") from None
        if graph.target_id != target or len({n.id for n in graph.nodes}) != len(graph.nodes):
            raise Rejected("upstream_graph_identity_mismatch")
        return graph

    async def rate_limit(self, audit, owner):
        async with self.rate_lock:
            delay = max(0, self.next_request - time.monotonic())
            if delay:
                await asyncio.sleep(delay)
            self.store.active(audit, owner)
            self.next_request = time.monotonic() + 1 / self.settings.requests_per_second

    async def execute(self, audit: str, owner: str, hypothesis: AttackHypothesis, probe: Probe, correlation: str, graph=None) -> ExecutionResult:
        execution_started = time.monotonic()
        result = ExecutionResult(audit_id=audit, hypothesis_id=hypothesis.id, correlation_id=correlation, op=probe.op, status="blocked")
        reserved = False
        try:
            a = self.store.active(audit, owner)
            target = self.settings.targets.get(a["target"])
            if not target:
                raise Rejected("target_not_authorized")
            graph = graph or await self.graph(a["target"], correlation)
            if graph.target_id != a["target"]:
                raise Rejected("target_graph_mismatch")
            state = self.store.read(audit, owner, secrets=True)
            node, rule, args = build_arguments(probe, hypothesis, graph, target, state)
            result.risk_classification = "safe"
            if len(hypothesis.attack_sequence) > self.settings.max_depth:
                raise Rejected("chain_depth_budget_exhausted")
            # Parent evidence is authoritative. A mutation cannot reset depth or
            # change the original hypothesis/op or run after a terminal category.
            if probe.parent_probe_id:
                parent = self.store.get_probe(audit, owner, probe.parent_probe_id)
                interpretation = parent["interpretation"]
                previous = parent["context"]["probe"]
                if not interpretation or interpretation["next_action"] != "mutate" or previous["hypothesis_id"] != probe.hypothesis_id or previous["op"] != probe.op or probe.depth != previous["depth"] + 1:
                    raise Rejected("invalid_mutation_parent")
                for name, value in probe.binding.headers.items():
                    if previous["binding"]["headers"].get(name) != value and value not in rule.header_variations.get(name, []):
                        raise Rejected("mutation_header_value_not_authorized")
            elif probe.depth != 0:
                raise Rejected("invalid_initial_depth")
            # Dependencies refer to completed steps of this hypothesis in this audit.
            current = next(s.step for s in hypothesis.attack_sequence if s.op == probe.op)
            required = set(probe.binding.depends_on) | {s.step for s in hypothesis.attack_sequence if s.step < current}
            trace = self.store.trace(audit, owner)["probes"]
            completed = {s.step for p in trace if p["result"] and p["result"]["status"] == "executed" and p["result"]["status_code"] in range(200, 300) and p["result"]["hypothesis_id"] == hypothesis.id for s in hypothesis.attack_sequence if s.op == p["result"]["op"]}
            if any(i >= current for i in required) or not required.issubset(completed):
                raise Rejected("unresolved_step_dependency")
            encoded = json.dumps(args.model_dump(mode="json"), sort_keys=True, allow_nan=False)
            if len(encoded.encode()) > self.settings.max_request_size:
                raise Rejected("request_too_large")
            result.request_fingerprint = hashlib.sha256(encoded.encode()).hexdigest()
            self.store.reserve(audit, owner, result, probe, hypothesis, graph)
            reserved = True
            async with self.semaphore:
                async with asyncio.timeout(min(self.settings.request_timeout, max(.001, a["created"] + self.settings.max_duration - time.time()))):
                    await self.http_request(args, target, node, rule, audit, owner, result)
            if result.parsed and result.status_code in range(200, 300):
                for key, value in result.parsed.artifacts.items():
                    category = "tokens" if key in result.parsed.credential_fields else "object_ids"
                    state_key = f"{node.id}.{key}"
                    self.store.write(audit, owner, StateWrite(category=category, key=state_key, value=value))
                    result.state_changes.append(f"{category}.{state_key}")
                # Credentials are never returned to C4 or clients. Stored only as
                # encrypted session artifacts and referenced by name thereafter.
                for key in result.parsed.credential_fields:
                    parts = key.split(".")
                    item = result.parsed.data
                    for part in parts[:-1]:
                        item = item[part]
                    item[parts[-1]] = "[REDACTED]"
                    result.parsed.artifacts[key] = "[REDACTED]"
            self.store.transition(audit, "INTERPRETING")
        except Rejected as exc:
            result.error = str(exc)
            result.approval_required = "approval_required" in result.error
            if result.approval_required:
                result.risk_classification = "destructive"
                if target and target.operations.get(probe.op) and target.operations[probe.op].risk != "safe":
                    result.risk_classification = target.operations[probe.op].risk
                await self.gate.approve(audit_id=audit, probe=probe)
                self.store.transition(audit, "AWAITING_APPROVAL")
            elif "budget" in result.error:
                result.status = "budget_exhausted"
            elif "duplicate" in result.error:
                result.status = "duplicate"
            elif "cancelled" in result.error:
                result.status = "cancelled"
        except (TimeoutError, httpx.TimeoutException):
            result.status, result.error = "error", "transport_timeout_not_proof_of_crash"
        except httpx.HTTPError:
            result.status, result.error = "error", "transport_failure"
        except (ValidationError, ValueError, TypeError):
            result.status, result.error = "blocked", "invalid_arguments_or_contract"
        finally:
            if result.attempts and not result.latency_ms:
                result.latency_ms = (time.monotonic() - execution_started) * 1000
            if reserved:
                self.store.finish(result)
            else:
                self.store.event(audit, "rejection", result.model_dump(mode="json"))
            logger.info("probe_result", extra={"audit_id": audit, "probe_id": result.probe_id, "correlation_id": correlation, "outcome": result.status, "error_code": result.error})
        return result

    async def http_request(self, args: HTTPArguments, target, node, rule, audit, owner, result):
        """Only callable with an already graph-validated/reserved probe context."""
        enforce_url(args.url, target)
        headers = args.headers.copy()
        headers["X-Correlation-ID"] = result.correlation_id
        headers["Accept-Encoding"] = "identity"  # do not decompress untrusted bombs
        if args.session_ref:
            state = self.store.read(audit, owner, secrets=True)
            token = state.values["tokens"].get(args.session_ref)
            cookie = state.values["cookies"].get(args.session_ref)
            if token is None and cookie is None:
                raise Rejected("missing_session_context")
            if token is not None:
                if not isinstance(token, str) or not 1 <= len(token) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token):
                    raise Rejected("invalid_session_token")
                if node.auth.type not in {"bearer", "api_key"} or node.auth.location != "header":
                    raise Rejected("unsupported_auth_scheme")
                if (node.auth.header_name or "Authorization").lower() not in {"authorization", "x-api-key", "api-key"}:
                    raise Rejected("unsupported_credential_header")
                headers[node.auth.header_name or "Authorization"] = ("Bearer " if node.auth.type == "bearer" else "") + token
            if cookie is not None:
                if not isinstance(cookie, str) or any(ord(c) < 32 or ord(c) > 126 for c in cookie):
                    raise Rejected("invalid_session_cookie")
                headers["Cookie"] = cookie
        kwargs = {"headers": headers, "params": args.params}
        if args.body is not None:
            if args.body_type == "json":
                kwargs["json"] = args.body
            elif args.body_type == "text" and isinstance(args.body, str):
                kwargs["content"] = args.body.encode()
            elif args.body_type == "form" and isinstance(args.body, dict):
                kwargs["data"] = args.body
            else:
                raise Rejected("invalid_body_encoding")
        start = time.monotonic()
        timeout = httpx.Timeout(self.settings.read_timeout, connect=self.settings.connect_timeout)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False, transport=self.transport) as client:
            for attempt in range(self.settings.retries + 1):
                await self.rate_limit(audit, owner)
                slot = f"{result.probe_id}-{attempt}"
                while True:
                    self.store.active(audit, owner)
                    delay = self.store.network_slot(slot)
                    if not delay:
                        break
                    await asyncio.sleep(delay)
                result.attempts += 1
                try:
                    async with client.stream(args.method, args.url, **kwargs) as response:
                        result.status_code = response.status_code
                        result.response_headers = redact(dict(response.headers))
                        if 300 <= response.status_code < 400 and response.headers.get("location"):
                            enforce_url(urljoin(args.url, response.headers["location"]), target)
                            raise Rejected("redirect_not_followed")
                        if response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise Rejected("encoded_response_not_supported")
                        data = bytearray()
                        async for chunk in response.aiter_raw(chunk_size=8192):
                            self.store.active(audit, owner)
                            if len(data) + len(chunk) > self.settings.max_response_size:
                                raise Rejected("response_too_large")
                            data.extend(chunk)
                        result.parsed = parse_response(bytes(data), response.headers.get("content-type", ""), node, response.status_code, rule.response_credentials)
                        result.status = "executed"
                        break
                except httpx.ConnectError:
                    if args.method not in {"GET", "HEAD", "OPTIONS"} or attempt >= self.settings.retries:
                        raise
                    await asyncio.sleep(min(.1 * (2 ** attempt), 1))
                finally:
                    self.store.network_slot(slot, release=True)
        result.latency_ms = (time.monotonic() - start) * 1000


def public_result(result):
    """Public evidence intentionally excludes arbitrary response and request text."""
    data = result.model_dump(mode="json") if hasattr(result, "model_dump") else result.copy()
    if data.get("parsed"):
        p = data["parsed"]
        p["data"] = {"evidence_available": True, "body_sha256": p["body_sha256"]}
        p["artifacts"] = {k: "[REDACTED]" for k in p["artifacts"]}
    public_headers = {}
    for k, v in data.get("response_headers", {}).items():
        if k == "content-type" and v.split(";")[0].lower() in {"application/json", "text/plain", "text/html", "application/octet-stream"}:
            public_headers[k] = v.split(";")[0].lower()
        elif k in {"content-length", "retry-after"} and v.isdigit():
            public_headers[k] = v
        else:
            public_headers[k] = "[REDACTED]"
    data["response_headers"] = public_headers
    return data
