import re
from typing import List, Dict, Any, Set
from sis.models import EndpointNode, ParameterModel
from sis.normalizer import SpecNormalizer


class AttackSurfaceTagger:
    """
    Static rule engine that annotates EndpointNodes with vulnerability candidates
    and security signals, independent of any LLM.
    """

    SENSITIVE_KEYWORDS: Set[str] = {
        "password", "pass", "passwd", "token", "jwt", "secret", "key",
        "private_key", "ssn", "credit_card", "cvv", "email", "phone",
        "hash", "session", "credential", "auth_token", "api_key",
        "refresh_token", "rsa", "bearer", "authorization", "salt",
        "pin", "passcode", "secret_key"
    }

    ADMIN_KEYWORDS: Set[str] = {
        "admin", "internal", "manage", "management", "sys", "system",
        "root", "maintenance", "debug", "purge", "config", "configuration",
        "dashboard", "supervisor", "priv", "console", "actuator"
    }

    ID_PARAM_PATTERN = re.compile(r"(^|_)(id|uuid|guid|num|pk|account|user|doc|order|item|profile)$", re.IGNORECASE)

    @classmethod
    def is_idor_param(cls, name: str, location: str) -> bool:
        """Determines if a parameter is likely a user-controllable object identifier."""
        name_clean = name.strip().lower()
        if cls.ID_PARAM_PATTERN.search(name_clean):
            return True
        if location == "path":
            # Any path param like {id}, {user_id}, {doc_id} is an IDOR candidate
            return True
        return False

    @classmethod
    def tag_nodes(cls, nodes: List[EndpointNode]) -> List[EndpointNode]:
        """
        Applies static tagging rules across all nodes in the target API surface,
        including cross-service correlation.
        """
        # Step 1: Map output fields produced by each service prefix
        service_outputs: Dict[str, Dict[str, str]] = {}  # service_prefix -> {field_name: op_id}
        for node in nodes:
            service = node.service_prefix or "default"
            if service not in service_outputs:
                service_outputs[service] = {}

            # Extract output property names from response schemas
            for resp_code, resp_schema in node.response_schemas.items():
                if str(resp_code).startswith("2"):
                    # Find schema inside content -> application/json or direct
                    schema = resp_schema.get("schema") or (
                        resp_schema.get("content", {}).get("application/json", {}).get("schema")
                    )
                    props = SpecNormalizer.extract_property_names(schema)
                    for prop in props:
                        service_outputs[service][prop.lower()] = node.id

            # Semantic output inference for minimal/stub specs
            path_lower = node.path.lower()
            if "token" in path_lower or "login" in path_lower or "auth" in path_lower:
                for f in ["token", "jwt", "service_token", "access_token", "user_id"]:
                    service_outputs[service][f] = node.id
            if "users" in path_lower or "profile" in path_lower:
                for f in ["user_id", "id", "doc_id", "tenant_id", "email"]:
                    service_outputs[service][f] = node.id

        # Step 2: Tag each node individually and cross-correlate
        for node in nodes:
            tags = set(node.attack_surface_tags)

            # Rule 1: IDOR Candidate
            has_idor_param = False
            for param in node.parameters:
                if cls.is_idor_param(param.name, param.location):
                    has_idor_param = True
                    break
            if has_idor_param:
                tags.add("idor_candidate")

            # Rule 2: State Mutation
            if node.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                tags.add("state_mutation")

            # Rule 3: Sensitive Response Data
            response_props: Set[str] = set()
            for resp_code, resp_schema in node.response_schemas.items():
                schema = resp_schema.get("schema") or (
                    resp_schema.get("content", {}).get("application/json", {}).get("schema")
                )
                response_props.update(SpecNormalizer.extract_property_names(schema))

            # Also check response description text for sensitive hints
            resp_text = str(node.response_schemas).lower()
            matching_sensitive = [k for k in cls.SENSITIVE_KEYWORDS if k in response_props or f'"{k}"' in resp_text]
            if matching_sensitive:
                tags.add("sensitive_response")

            # Rule 4: Admin / Internal Surface
            path_lower = node.path.lower()
            summary_lower = (node.summary or "").lower()
            is_admin = False
            for admin_kw in cls.ADMIN_KEYWORDS:
                if f"/{admin_kw}" in path_lower or f"_{admin_kw}" in path_lower or f"-{admin_kw}" in path_lower:
                    is_admin = True
                    break
                if admin_kw in summary_lower:
                    is_admin = True
                    break
            if is_admin:
                tags.add("admin_surface")

            # Rule 5: Weak or No Auth on Sensitive / Mutating Endpoints
            if node.auth.type == "none" and ("state_mutation" in tags or "admin_surface" in tags):
                tags.add("unauthenticated_sensitive_action")

            # Rule 6: Cross-Service Parameter
            # A parameter on this operation was output by a *different* service prefix
            current_service = node.service_prefix or "default"
            input_fields: Set[str] = {p.name.lower() for p in node.parameters}
            if node.request_body_schema:
                body_props = SpecNormalizer.extract_property_names(node.request_body_schema)
                input_fields.update(body_props)

            for other_service, outputs in service_outputs.items():
                if other_service == current_service:
                    continue
                for in_field in input_fields:
                    # Direct match or common ID alias
                    if in_field in outputs:
                        tags.add(f"cross_service_param:{in_field}")
                    elif in_field == "id" and "user_id" in outputs:
                        tags.add("cross_service_param:user_id")
                    elif in_field == "user_id" and "id" in outputs:
                        tags.add("cross_service_param:id")
                    elif in_field == "doc_id" and ("doc_id" in outputs or "document_id" in outputs):
                        tags.add("cross_service_param:doc_id")
                    elif "user" in in_field and "user_id" in outputs:
                        tags.add("cross_service_param:user_id")

            # Rule 7: Preserve any inherent OWASP tags (e.g. from DVWS)
            if "owasp_category" in node.metadata:
                tags.add(f"owasp:{node.metadata['owasp_category']}")

            node.attack_surface_tags = sorted(list(tags))

        return nodes
