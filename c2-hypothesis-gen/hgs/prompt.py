import json
from typing import Dict, Any, List, Optional
from hgs.config import settings


class PromptAssembler:
    """
    Assembles structured prompts with hierarchical subgraph summarization
    and JSON Schema tool definitions for LLM planner calls.
    """

    OWASP_TAXONOMY_GUIDE = """
OWASP API Security Top 10 Taxonomy:
- API1:2023 - Broken Object Level Authorization (BOLA): Attackers access resources by altering identifier parameters in API calls (e.g. {id}, {user_id}, {doc_id}).
- API2:2023 - Broken Authentication: Poorly implemented authentication mechanics allow credential stuffing, token forgery, or improper delegation.
- API3:2023 - Broken Object Property Level Authorization (BOPLA): Excessive data exposure of sensitive response fields or unauthorized mass assignment in updates.
- API5:2023 - Broken Function Level Authorization (BFLA): Non-privileged users executing administrative/maintenance actions (e.g. /admin, /purge, /config).
- API8:2023 - Security Misconfiguration: Unprotected debug interfaces, exposed environment variables, verbose stack traces, or default configs.
"""

    EMIT_HYPOTHESES_TOOL = {
        "name": "emit_hypotheses",
        "description": "Emit structured, prioritized attack hypotheses targeting the API endpoint graph.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "Hypothesis ID (e.g. hyp_1)"},
                            "target_endpoints": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of actual operation node IDs in the graph targeted"
                            },
                            "owasp_category": {
                                "type": "string",
                                "description": "OWASP category e.g. API1:BOLA, API2:Broken_Auth, API5:BFLA"
                            },
                            "attack_sequence": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "step": {"type": "integer"},
                                        "op": {"type": "string", "description": "Operation node ID"},
                                        "notes": {"type": "string"}
                                    },
                                    "required": ["step", "op", "notes"]
                                }
                            },
                            "initial_payload": {
                                "type": "object",
                                "description": "Headers, params, or body payload to probe"
                            },
                            "rationale": {"type": "string", "description": "Why this hypothesis is valid based on graph signals"},
                            "impact_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                            "likelihood_score": {"type": "number", "minimum": 0.0, "maximum": 1.0}
                        },
                        "required": ["id", "target_endpoints", "owasp_category", "attack_sequence", "rationale", "impact_score", "likelihood_score"]
                    }
                }
            },
            "required": ["hypotheses"]
        }
    }

    @classmethod
    def summarize_graph(cls, attack_surface: Dict[str, Any], budget: int = settings.context_node_budget) -> Dict[str, Any]:
        """
        Hierarchical graph summarization: groups operations by service prefix.
        If node count exceeds budget, summarizes low-priority nodes to prevent context blowup.
        """
        nodes = attack_surface.get("nodes", [])
        edges = attack_surface.get("edges", [])

        # Group by service prefix
        services: Dict[str, List[Dict[str, Any]]] = {}
        for n in nodes:
            srv = n.get("service_prefix") or "general"
            if srv not in services:
                services[srv] = []
            services[srv].append(n)

        # Service overview
        service_overview = {
            srv: {
                "total_operations": len(ops),
                "mutating_ops": sum(1 for o in ops if o.get("method") in ["POST", "PUT", "DELETE"]),
                "sample_paths": [f"{o.get('method')} {o.get('path')}" for o in ops[:3]]
            }
            for srv, ops in services.items()
        }

        # Filter detailed operations within budget
        detailed_nodes = []
        for n in nodes[:budget]:
            detailed_nodes.append({
                "id": n.get("id"),
                "method": n.get("method"),
                "path": n.get("path"),
                "parameters": [p.get("name") for p in n.get("parameters", [])],
                "auth": n.get("auth", {}).get("type", "none"),
                "attack_surface_tags": n.get("attack_surface_tags", []),
            })

        # Key cross-service edges
        cross_edges = [
            {
                "from": e.get("from_node"),
                "to": e.get("to_node"),
                "relation": e.get("relation"),
                "field": e.get("field"),
                "confidence": e.get("confidence"),
            }
            for e in edges if e.get("metadata", {}).get("cross_service", False) or e.get("confidence", 0) >= 0.75
        ]

        return {
            "service_overview": service_overview,
            "detailed_operations": detailed_nodes,
            "key_dependency_edges": cross_edges[:20],
        }

    @classmethod
    def build_system_prompt(cls) -> str:
        return (
            "You are PenAgent's Attack Hypothesis Generator (Component 2).\n"
            "Your role is to analyze an API Endpoint Graph, identify trust-boundary vulnerabilities and multi-step exploit chains, "
            "and emit structured, highly prioritized attack hypotheses.\n"
            "CRITICAL: Every endpoint ID referenced in target_endpoints and attack_sequence MUST match an exact node ID from the graph.\n"
            "Do NOT invent fictional endpoints."
        )

    @classmethod
    def build_user_prompt(
        cls,
        target_id: str,
        graph_summary: Dict[str, Any],
        candidates: Dict[str, List[Dict[str, Any]]],
        mode: str = "initial",
        knowledge_state: Optional[Dict[str, Any]] = None,
        prior_findings: Optional[List[Dict[str, Any]]] = None,
        max_hypotheses: int = 15,
    ) -> str:
        prompt_parts = [
            f"# Target Audit Context: {target_id}",
            f"Mode: {mode.upper()}",
            cls.OWASP_TAXONOMY_GUIDE,
            "## Current Knowledge State:",
            json.dumps(knowledge_state or {}, indent=2),
        ]

        if prior_findings:
            prompt_parts.extend([
                "## Prior Findings & Leaked Artifacts (Exploit in replan):",
                json.dumps(prior_findings, indent=2),
            ])

        prompt_parts.extend([
            "## Endpoint Graph Summary:",
            json.dumps(graph_summary, indent=2),
            f"\nEmit up to {max_hypotheses} hypotheses ranked by impact × likelihood. Prioritize cross-service chains following key dependency edges."
        ])

        return "\n\n".join(prompt_parts)
