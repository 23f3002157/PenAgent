"""Minimal resumable C1→C2→C3↔C4 path; no claim of a LangGraph runtime."""
from urllib.parse import quote
from uuid import uuid4
from pydantic import ValidationError

from hgs.models import AttackHypothesis
from penagent_common.http import service_call
from penagent_common.models import Binding, Interpretation, Mutation, Probe, StateWrite, Category
from penagent_common.policy import Rejected


class Workflow:
    def __init__(self, executor):
        self.executor = executor
        self.settings, self.store = executor.settings, executor.store

    def save(self, audit, owner, value):
        self.store.checkpoint(audit, owner, value)

    async def run(self, audit, owner, bindings, correlation):
        holder = uuid4().hex
        self.store.lease(audit, owner, holder)
        try:
            return await self._run(audit, owner, bindings, correlation)
        except Rejected as exc:
            self.store.event(audit, "workflow_blocked", {"error": str(exc)})
            return {"status": "blocked", "error": str(exc)}
        except ValidationError:
            self.store.event(audit, "workflow_blocked", {"error": "upstream_or_checkpoint_contract_violation"})
            return {"status": "blocked", "error": "upstream_or_checkpoint_contract_violation"}
        finally:
            self.store.lease(audit, owner, holder, release=True)

    async def _run(self, audit, owner, bindings, correlation):
        a = self.store.active(audit, owner)
        saved = self.store.read(audit, owner, secrets=True).values["observations"].get("__workflow")
        if saved and saved.get("phase") == "uncertain":
            raise Rejected("interrupted_request_requires_operator_review_no_replay")
        if not saved or saved.get("phase") == "done":
            # Persist before the non-idempotent HGS queue pop. Recovery must never
            # silently lose a popped hypothesis or consume another one.
            self.save(audit, owner, {"phase": "uncertain"})
            self.store.transition(audit, "PLANNING")
            data = await service_call(self.settings, "GET", self.settings.hgs_url,
                         f"/v1/queue/{quote(a['target'], safe='')}/next", correlation_id=correlation)
            if data is None:
                self.save(audit, owner, {"phase": "done"})
                self.store.transition(audit, "REPORTING")
                return {"status": "queue_empty", "report": "execution trace available; Component 6 is not implemented"}
            hyp = AttackHypothesis.model_validate(data)
            saved = {"phase": "ready", "hypothesis": hyp.model_dump(mode="json"), "index": 0, "bindings": {k: v.model_dump() for k, v in bindings.items()}}
            self.save(audit, owner, saved)
        hyp = AttackHypothesis.model_validate(saved["hypothesis"])
        if not hyp.attack_sequence:
            raise Rejected("empty_hypothesis_sequence")
        last = None
        while saved["index"] < len(hyp.attack_sequence):
            self.store.active(audit, owner)
            step = hyp.attack_sequence[saved["index"]]
            if saved["phase"] == "ready":
                raw_binding = saved["bindings"].get(str(step.step))
                if raw_binding is None:
                    # HGS hint semantics are not executable contracts. Accept only
                    # explicit namespaced binding shapes, never heuristic strings.
                    hint = step.payload_hint or (hyp.initial_payload if len(hyp.attack_sequence) == 1 else {})
                    if hint and not set(hint).issubset(Binding.model_fields):
                        raise Rejected("unresolved_hypothesis_payload_hint_supply_step_binding")
                    raw_binding = hint
                probe = Probe(hypothesis_id=hyp.id, op=step.op, binding=Binding.model_validate(raw_binding))
            elif saved["phase"] == "mutation_ready":
                probe = Probe.model_validate(saved["next_probe"])
            else:
                probe = Probe.model_validate(saved["probe"])
            if saved["phase"] in {"ready", "mutation_ready"}:
                saved.update(phase="uncertain", probe=probe.model_dump())
                self.save(audit, owner, saved)
                result = await self.executor.execute(audit, owner, hyp, probe, correlation)
                saved.update(phase="interpreting", result=result.model_dump(mode="json"))
                self.save(audit, owner, saved)
            result = saved["result"]
            if result["status"] != "executed":
                saved["phase"] = "done"
                self.save(audit, owner, saved)
                return {"status": result["status"], "error": result["error"], "probe_id": result["probe_id"]}
            # C4 independently loads stored evidence, not caller-asserted results.
            raw = await service_call(self.settings, "POST", self.settings.interpreter_url,
                f"/v1/audits/{audit}/interpret", payload={"owner": owner, "probe_id": result["probe_id"]}, correlation_id=correlation)
            last = Interpretation.model_validate(raw)
            if last.next_action == "stop":
                # Stopping target execution must not discard a confirmed finding
                # from the planner. A 5xx halt remains local and never restarts it.
                if last.classification != Category.ERROR_CRASH:
                    await self.handoff(audit, owner, a["target"], hyp, last, correlation)
                saved["phase"] = "done"
                self.save(audit, owner, saved)
                self.store.transition(audit, "REPORTING")
                return {"status": "chain_halted", "interpretation": last.model_dump(mode="json")}
            if last.next_action == "mutate":
                raw = await service_call(self.settings, "POST", self.settings.interpreter_url,
                    f"/v1/audits/{audit}/mutations", payload={"owner": owner, "probe_id": result["probe_id"]}, correlation_id=correlation)
                if raw:
                    mutation = Mutation.model_validate(raw)
                    if mutation.original_hypothesis_id != hyp.id or mutation.observation_id != result["probe_id"]:
                        raise Rejected("mutation_contract_mismatch")
                    saved.update(phase="mutation_ready", next_probe=mutation.probe.model_dump())
                    self.save(audit, owner, saved)
                    continue
            # Bounded, no-secret planner handoff. Pending means outcome unknown;
            # never auto-repeat a potentially side-effecting planner request.
            await self.handoff(audit, owner, a["target"], hyp, last, correlation)
            if last.next_action in {"replan", "next_hypothesis"}:
                saved["phase"] = "done"
                self.save(audit, owner, saved)
                self.store.transition(audit, "PLANNING")
                return {"status": "hypothesis_finished", "interpretation": last.model_dump(mode="json")}
            saved.update(phase="ready", index=saved["index"] + 1)
            self.save(audit, owner, saved)
        saved["phase"] = "done"
        self.save(audit, owner, saved)
        self.store.transition(audit, "PLANNING")
        return {"status": "hypothesis_finished", "interpretation": last.model_dump(mode="json") if last else None}

    async def handoff(self, audit, owner, target, hypothesis, output, correlation):
        probe_id = output.probe_id
        for kind in ["feedback"] + (["replan"] if output.replan_justified else []):
            status = self.store.handoff(audit, probe_id, kind)
            if status == "done":
                continue
            if status == "pending":
                raise Rejected("planner_handoff_outcome_unknown")
            self.store.active(audit, owner)
            self.store.handoff(audit, probe_id, kind, "pending")
            if kind == "feedback":
                path = f"/v1/hypotheses/{quote(hypothesis.id, safe='')}/feedback"
                payload = {"outcome": output.classification.value.lower(), "evidence": probe_id, "discovered_state": {}}
            else:
                self.store.transition(audit, "REPLANNING")
                path = "/v1/events/replan"
                payload = {"target_id": target, "finding_id": probe_id, "owasp_category": hypothesis.owasp_category,
                           "knowledge_delta": {"evidence_ref": probe_id, "classification": output.classification.value}}
            await service_call(self.settings, "POST", self.settings.hgs_url, path, payload=payload, correlation_id=correlation)
            self.store.handoff(audit, probe_id, kind, "done")
