from typing import Dict, Any, List, Set, Optional
import httpx
from hgs.config import settings


class CandidateSurfacer:
    """
    Reads attack_surface_tags from SIS's attack-surface view and buckets endpoints
    into candidate groups by OWASP API Top-10 categories.
    """

    OWASP_MAPPING = {
        "idor_candidate": "API1:BOLA",
        "cross_service_param": "API1:BOLA",
        "sensitive_response": "API3:BOPLA",
        "unauthenticated_sensitive_action": "API5:BFLA",
        "admin_surface": "API5:BFLA",
        "state_mutation": "API5:BFLA",
    }

    def __init__(self, sis_url: Optional[str] = None):
        self.sis_url = sis_url or settings.sis_url

    async def fetch_attack_surface(self, target_id: str) -> Dict[str, Any]:
        """Queries Spec Ingestion Service for target attack surface view."""
        url = f"{self.sis_url.rstrip('/')}/v1/graph/{target_id}/attack-surface"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.json()
        except Exception:
            pass
        return {}

    def surface_candidates(self, attack_surface_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Buckets endpoint nodes by OWASP API Top-10 categories based on attack-surface signals.
        Returns: {owasp_category: [candidate_endpoint_dicts]}
        """
        nodes = attack_surface_data.get("nodes", [])
        candidates_by_category: Dict[str, List[Dict[str, Any]]] = {
            "API1:BOLA": [],
            "API2:Broken_Auth": [],
            "API3:BOPLA": [],
            "API5:BFLA": [],
            "API8:Security_Misconfiguration": [],
        }

        for node in nodes:
            tags = set(node.get("attack_surface_tags", []))
            path_lower = node.get("path", "").lower()
            method_upper = node.get("method", "").upper()
            auth = node.get("auth", {})
            auth_type = auth.get("type", "none") if isinstance(auth, dict) else "none"

            # Check explicit OWASP tags (e.g. from DVWS or metadata)
            for t in tags:
                if t.startswith("owasp:"):
                    cat = t.replace("owasp:", "").strip()
                    if "API1" in cat:
                        candidates_by_category["API1:BOLA"].append(node)
                    elif "API2" in cat:
                        candidates_by_category["API2:Broken_Auth"].append(node)
                    elif "API3" in cat:
                        candidates_by_category["API3:BOPLA"].append(node)
                    elif "API5" in cat:
                        candidates_by_category["API5:BFLA"].append(node)
                    elif "API8" in cat:
                        candidates_by_category["API8:Security_Misconfiguration"].append(node)

            # Rule 1: API1: BOLA (IDOR candidates & cross-service parameters)
            if "idor_candidate" in tags or any("cross_service_param" in t for t in tags):
                if node not in candidates_by_category["API1:BOLA"]:
                    candidates_by_category["API1:BOLA"].append(node)

            # Rule 2: API2: Broken Authentication (Login, auth, token exchange routes)
            if any(k in path_lower for k in ["login", "token", "auth", "session", "oauth"]):
                if node not in candidates_by_category["API2:Broken_Auth"]:
                    candidates_by_category["API2:Broken_Auth"].append(node)

            # Rule 3: API3: BOPLA (Sensitive response exposure or mass assignment)
            if "sensitive_response" in tags or (method_upper in ["PUT", "PATCH"] and "profile" in path_lower):
                if node not in candidates_by_category["API3:BOPLA"]:
                    candidates_by_category["API3:BOPLA"].append(node)

            # Rule 4: API5: BFLA (Admin surfaces, unauthenticated mutations, maintenance purge)
            if "admin_surface" in tags or "unauthenticated_sensitive_action" in tags:
                if node not in candidates_by_category["API5:BFLA"]:
                    candidates_by_category["API5:BFLA"].append(node)

            # Rule 5: API8: Security Misconfiguration (Debug, env, config, actuator)
            if any(k in path_lower for k in ["debug", "env", "config", "actuator", "status", "version"]):
                if node not in candidates_by_category["API8:Security_Misconfiguration"]:
                    candidates_by_category["API8:Security_Misconfiguration"].append(node)

        return candidates_by_category
