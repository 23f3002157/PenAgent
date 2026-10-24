"""HGS-compatible function tool definitions with strict validation at invocation.

Tools are bound to an authenticated audit and graph operation by the host agent;
these identities are not LLM arguments. No dynamic Python evaluation is used.
"""
from pydantic import ValidationError
from penagent_common.models import HTTPArguments, Empty, ParseArguments, StateWrite, Probe, Binding
from penagent_common.policy import Rejected
from executor.service import public_result
from executor.validation import build_arguments


class Tools:
    schemas = {"http_request": HTTPArguments, "parse_response": ParseArguments,
               "read_session_state": Empty, "write_session_state": StateWrite}

    def __init__(self, executor, audit, owner, hypothesis, probe, correlation):
        self.executor, self.audit, self.owner = executor, audit, owner
        self.hypothesis, self.probe, self.correlation = hypothesis, probe, correlation

    @classmethod
    def definitions(cls):
        return [{"type": "function", "function": {"name": name, "description": name.replace("_", " "),
                  "parameters": schema.model_json_schema()}} for name, schema in cls.schemas.items()]

    async def invoke(self, name, arguments):
        try:
            if name not in self.schemas:
                raise Rejected("unknown_tool")
            args = self.schemas[name].model_validate(arguments)
            store = self.executor.store
            store.active(self.audit, self.owner)
            if name == "read_session_state":
                return store.read(self.audit, self.owner).model_dump()
            if name == "write_session_state":
                # Only observations may be authored by a model. Extracted IDs and
                # credentials are written by the parser or authenticated operator.
                if args.category != "observations" or args.key.startswith("__"):
                    raise Rejected("tool_cannot_fabricate_session_artifacts")
                return store.write(self.audit, self.owner, args).model_dump()
            if name == "parse_response":
                item = store.get_probe(self.audit, self.owner, args.probe_id)
                if not item["result"]:
                    raise Rejected("probe_outcome_unknown_do_not_replay")
                return public_result(item["result"])["parsed"]
            audit = store.audit(self.audit, self.owner)
            target = self.executor.settings.targets[audit["target"]]
            graph = await self.executor.graph(audit["target"], self.correlation)
            state = store.read(self.audit, self.owner, secrets=True)
            _, _, expected = build_arguments(self.probe, self.hypothesis, graph, target, state)
            if args.url != expected.url or args.method != expected.method:
                raise Rejected("tool_endpoint_mismatch")
            binding = self.probe.binding.model_copy(update={"query": args.params, "headers": args.headers,
                       "body": args.body, "body_type": args.body_type, "session_ref": args.session_ref})
            candidate = self.probe.model_copy(update={"binding": binding})
            result = await self.executor.execute(self.audit, self.owner, self.hypothesis, candidate, self.correlation, graph)
            return public_result(result)
        except (ValidationError, Rejected, KeyError):
            return {"status": "blocked", "error": "invalid_tool_arguments_or_policy"}
