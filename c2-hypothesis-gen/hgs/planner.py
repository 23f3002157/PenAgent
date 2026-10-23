import json
import uuid
from typing import List, Dict, Any, Optional
import httpx
from hgs.models import AttackHypothesis, AttackSequenceStep, Provenance
from hgs.prompt import PromptAssembler
from hgs.config import settings


class Planner:
    """
    Orchestrates the Planner LLM invocation (Anthropic Claude or OpenAI)
    with strict tool-calling schema. Includes a deterministic heuristic planner
    as an offline/mock fallback for reproducible testing and zero-cost local runs.
    """

    def __init__(self):
        self.anthropic_key = settings.anthropic_api_key
        self.openai_key = settings.openai_api_key

    async def generate_hypotheses(
        self,
        target_id: str,
        attack_surface: Dict[str, Any],
        candidates: Dict[str, List[Dict[str, Any]]],
        mode: str = "initial",
        knowledge_state: Optional[Dict[str, Any]] = None,
        prior_findings: Optional[List[Dict[str, Any]]] = None,
        max_hypotheses: int = 15,
    ) -> List[AttackHypothesis]:
        """Generates raw hypotheses via LLM or deterministic rule-based planner."""
        # 1. Check if live LLM keys are configured
        if self.anthropic_key:
            try:
                return await self._call_anthropic(
                    target_id, attack_surface, candidates, mode, knowledge_state, prior_findings, max_hypotheses
                )
            except Exception as e:
                pass

        if self.openai_key:
            try:
                return await self._call_openai(
                    target_id, attack_surface, candidates, mode, knowledge_state, prior_findings, max_hypotheses
                )
            except Exception as e:
                pass

        # 2. Deterministic Heuristic Planner Fallback
        return self._generate_heuristic_hypotheses(
            target_id, attack_surface, candidates, mode, knowledge_state, prior_findings, max_hypotheses
        )

    def _generate_heuristic_hypotheses(
        self,
        target_id: str,
        attack_surface: Dict[str, Any],
        candidates: Dict[str, List[Dict[str, Any]]],
        mode: str,
        knowledge_state: Optional[Dict[str, Any]],
        prior_findings: Optional[List[Dict[str, Any]]],
        max_hypotheses: int,
    ) -> List[AttackHypothesis]:
        """
        Synthesizes structured, valid attack hypotheses directly from graph topology,
        attack surface tags, and dependency edges.
        """
        hypotheses: List[AttackHypothesis] = []
        edges = attack_surface.get("edges", [])
        all_nodes = attack_surface.get("nodes", [])
        node_map = {n["id"]: n for n in all_nodes}

        # Index incoming edges for multi-step chaining
        to_edges: Dict[str, List[Dict[str, Any]]] = {}
        for e in edges:
            to_n = e.get("to_node")
            if to_n not in to_edges:
                to_edges[to_n] = []
            to_edges[to_n].append(e)

        # 1. API1: BOLA Hypotheses (including cross-service chains)
        for node in candidates.get("API1:BOLA", []):
            nid = node["id"]
            incoming = to_edges.get(nid, [])

            # Check if there is a multi-step chain (e.g. Auth -> User -> Vault)
            chained_steps = []
            target_eps = [nid]

            if incoming:
                # Find best producer
                producer_edge = max(incoming, key=lambda e: e.get("confidence", 0))
                prod_id = producer_edge.get("from_node")

                # Check if producer itself has an incoming producer (e.g. Auth -> User)
                grandparent_incoming = to_edges.get(prod_id, [])
                if grandparent_incoming:
                    gp_edge = max(grandparent_incoming, key=lambda e: e.get("confidence", 0))
                    gp_id = gp_edge.get("from_node")
                    if gp_id in node_map:
                        chained_steps.append(AttackSequenceStep(
                            step=1, op=gp_id, notes=f"Acquire initial credentials/token from {node_map[gp_id].get('path')}"
                        ))
                        target_eps.insert(0, gp_id)

                if prod_id in node_map and prod_id not in [s.op for s in chained_steps]:
                    step_num = len(chained_steps) + 1
                    chained_steps.append(AttackSequenceStep(
                        step=step_num, op=prod_id, notes=f"Extract dependent identifier '{producer_edge.get('field')}' from {node_map[prod_id].get('path')}"
                    ))
                    if prod_id not in target_eps:
                        target_eps.insert(-1, prod_id)

            # Final target step
            chained_steps.append(AttackSequenceStep(
                step=len(chained_steps) + 1,
                op=nid,
                notes=f"Attempt object-level access violation on {node.get('path')} using altered or cross-tenant ID"
            ))

            is_cross = any("cross_service_param" in t for t in node.get("attack_surface_tags", []))
            hyp = AttackHypothesis(
                id=f"hyp_{uuid.uuid4().hex[:6]}",
                target_endpoints=target_eps,
                owasp_category="API1:BOLA",
                attack_sequence=chained_steps,
                initial_payload={"test_id": "alternate_tenant_id"},
                rationale=f"IDOR candidate on {node.get('path')}" + (" via cross-service trust boundary" if is_cross else ""),
                impact_score=0.85 if is_cross else 0.78,
                likelihood_score=0.80 if is_cross else 0.70,
                priority=0.68,
                status="pending",
                provenance=Provenance.REPLAN if mode == "replan" else Provenance.INITIAL_PLAN,
                metadata={"cross_service": is_cross},
            )
            hypotheses.append(hyp)

        # 2. API2: Broken Authentication
        for node in candidates.get("API2:Broken_Auth", []):
            hyp = AttackHypothesis(
                id=f"hyp_{uuid.uuid4().hex[:6]}",
                target_endpoints=[node["id"]],
                owasp_category="API2:Broken_Auth",
                attack_sequence=[
                    AttackSequenceStep(step=1, op=node["id"], notes="Test authentication bypass / token forgery")
                ],
                initial_payload={"username": "admin' OR 1=1--"},
                rationale=f"Authentication endpoint {node.get('path')} vulnerable to token manipulation or auth bypass",
                impact_score=0.88,
                likelihood_score=0.65,
                priority=0.57,
                status="pending",
                provenance=Provenance.INITIAL_PLAN,
            )
            hypotheses.append(hyp)

        # 3. API3: BOPLA / Sensitive Data Exposure
        for node in candidates.get("API3:BOPLA", []):
            hyp = AttackHypothesis(
                id=f"hyp_{uuid.uuid4().hex[:6]}",
                target_endpoints=[node["id"]],
                owasp_category="API3:BOPLA",
                attack_sequence=[
                    AttackSequenceStep(step=1, op=node["id"], notes="Inspect response for excessive sensitive properties or mass assignment")
                ],
                initial_payload={"role": "admin", "is_admin": True},
                rationale=f"Response schema exposes sensitive attributes on {node.get('path')}",
                impact_score=0.72,
                likelihood_score=0.75,
                priority=0.54,
                status="pending",
                provenance=Provenance.INITIAL_PLAN,
            )
            hypotheses.append(hyp)

        # 4. API5: BFLA / Admin Surface
        for node in candidates.get("API5:BFLA", []):
            hyp = AttackHypothesis(
                id=f"hyp_{uuid.uuid4().hex[:6]}",
                target_endpoints=[node["id"]],
                owasp_category="API5:BFLA",
                attack_sequence=[
                    AttackSequenceStep(step=1, op=node["id"], notes="Attempt privileged/administrative action with low or no authentication")
                ],
                initial_payload={},
                rationale=f"Administrative/mutating action {node.get('method')} {node.get('path')} accessible without strict role check",
                impact_score=0.82,
                likelihood_score=0.68,
                priority=0.56,
                status="pending",
                provenance=Provenance.INITIAL_PLAN,
            )
            hypotheses.append(hyp)

        # 5. API8: Security Misconfiguration
        for node in candidates.get("API8:Security_Misconfiguration", []):
            hyp = AttackHypothesis(
                id=f"hyp_{uuid.uuid4().hex[:6]}",
                target_endpoints=[node["id"]],
                owasp_category="API8:Security_Misconfiguration",
                attack_sequence=[
                    AttackSequenceStep(step=1, op=node["id"], notes="Retrieve debug/environment variables or internal stack configuration")
                ],
                initial_payload={},
                rationale=f"Debug endpoint {node.get('path')} potentially exposes internal environment or stack config",
                impact_score=0.65,
                likelihood_score=0.72,
                priority=0.47,
                status="pending",
                provenance=Provenance.INITIAL_PLAN,
            )
            hypotheses.append(hyp)

        return hypotheses[:max_hypotheses]

    async def _call_anthropic(self, target_id, attack_surface, candidates, mode, knowledge_state, prior_findings, max_hypotheses):
        """Live Anthropic Claude Sonnet call with forced tool use."""
        summary = PromptAssembler.summarize_graph(attack_surface)
        user_prompt = PromptAssembler.build_user_prompt(
            target_id, summary, candidates, mode, knowledge_state, prior_findings, max_hypotheses
        )

        headers = {
            "x-api-key": self.anthropic_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": settings.anthropic_model,
            "max_tokens": 4096,
            "system": PromptAssembler.build_system_prompt(),
            "messages": [{"role": "user", "content": user_prompt}],
            "tools": [PromptAssembler.EMIT_HYPOTHESES_TOOL],
            "tool_choice": {"type": "tool", "name": "emit_hypotheses"},
            "temperature": 0.0,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for content in data.get("content", []):
                    if content.get("type") == "tool_use" and content.get("name") == "emit_hypotheses":
                        raw_hyps = content.get("input", {}).get("hypotheses", [])
                        return [AttackHypothesis.model_validate(h) for h in raw_hyps]
        raise RuntimeError(f"Anthropic call failed with status {resp.status_code}")

    async def _call_openai(self, target_id, attack_surface, candidates, mode, knowledge_state, prior_findings, max_hypotheses):
        """Live OpenAI API call with function calling."""
        summary = PromptAssembler.summarize_graph(attack_surface)
        user_prompt = PromptAssembler.build_user_prompt(
            target_id, summary, candidates, mode, knowledge_state, prior_findings, max_hypotheses
        )

        headers = {
            "Authorization": f"Bearer {self.openai_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.openai_model,
            "messages": [
                {"role": "system", "content": PromptAssembler.build_system_prompt()},
                {"role": "user", "content": user_prompt},
            ],
            "tools": [{"type": "function", "function": PromptAssembler.EMIT_HYPOTHESES_TOOL}],
            "tool_choice": {"type": "function", "function": {"name": "emit_hypotheses"}},
            "temperature": 0.0,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                tool_call = data["choices"][0]["message"]["tool_calls"][0]
                args = json.loads(tool_call["function"]["arguments"])
                return [AttackHypothesis.model_validate(h) for h in args.get("hypotheses", [])]
        raise RuntimeError(f"OpenAI call failed with status {resp.status_code}")
