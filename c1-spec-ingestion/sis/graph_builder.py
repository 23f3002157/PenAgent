import re
from typing import Dict, Any, List, Set, Tuple, Optional
import networkx as nx

from sis.models import (
    EndpointNode,
    EndpointEdge,
    EndpointGraph,
    ParameterModel,
    AuthInfo,
)
from sis.normalizer import SpecNormalizer
from sis.tagger import AttackSurfaceTagger


class GraphBuilder:
    """
    Constructs a directed operation graph (NetworkX DiGraph) from normalized OpenAPI IR.
    Infers dependency and call-order edges via:
      1. OpenAPI links objects (confidence 0.95)
      2. Producer-consumer parameter matching (confidence 0.80 - 0.85)
      3. Shared schema fields across request/response (confidence 0.65 - 0.70)
    """

    def __init__(self):
        self.nx_graph = nx.DiGraph()

    @staticmethod
    def extract_service_prefix(path: str) -> str:
        """
        Extracts logical service name or top-level resource prefix from URI path.
        Examples:
          /auth/v1/exchange-token -> 'auth'
          /users/v1/profile/{user_id} -> 'users'
          /vault/v1/documents/{doc_id} -> 'vault'
          /api/Users/{id} -> 'users'
          /rest/user/login -> 'user'
          /v2/users -> 'users'
        """
        clean = path.strip("/").lower()
        parts = clean.split("/")
        
        # Skip generic API prefixes
        ignore = {"api", "rest", "v1", "v2", "v3", "v4"}
        for part in parts:
            if part not in ignore and not part.startswith("{"):
                return part
        return parts[0] if parts else "root"

    @staticmethod
    def generate_operation_id(method: str, path: str, raw_op_id: Optional[str] = None) -> str:
        """Generates a clean, deterministic operation node ID."""
        if raw_op_id:
            cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", raw_op_id).strip("_").lower()
            return f"op_{cleaned}"
        
        service = GraphBuilder.extract_service_prefix(path)
        clean_path = re.sub(r"[/{}]", "_", path).strip("_")
        clean_path = re.sub(r"_+", "_", clean_path).lower()
        return f"op_{service}_{method.lower()}_{clean_path}"

    @staticmethod
    def extract_auth_info(op_dict: Dict[str, Any], root_doc: Dict[str, Any]) -> AuthInfo:
        """Extracts security schemes and scopes for an operation."""
        # Check operation-level security, fallback to root security
        sec_requirements = op_dict.get("security")
        if sec_requirements is None:
            sec_requirements = root_doc.get("security", [])

        if not sec_requirements or not isinstance(sec_requirements, list) or len(sec_requirements) == 0:
            return AuthInfo(type="none", scopes=[])

        # Security requirement is a dict: {scheme_name: [scopes]}
        first_req = sec_requirements[0]
        if not isinstance(first_req, dict) or not first_req:
            return AuthInfo(type="none", scopes=[])

        scheme_name = list(first_req.keys())[0]
        scopes = first_req[scheme_name] if isinstance(first_req[scheme_name], list) else []

        # Lookup scheme definition in components
        schemes = root_doc.get("components", {}).get("securitySchemes", {})
        scheme_def = schemes.get(scheme_name, {})
        scheme_type = scheme_def.get("type", "unknown").lower()
        http_scheme = scheme_def.get("scheme", "").lower()

        resolved_type = "custom"
        header_name = scheme_def.get("name")
        location = scheme_def.get("in", "header")

        if scheme_type == "http":
            if http_scheme == "bearer":
                resolved_type = "bearer"
            elif http_scheme == "basic":
                resolved_type = "basic"
            else:
                resolved_type = http_scheme or "http"
        elif scheme_type == "apikey":
            resolved_type = "api_key"
        elif scheme_type == "oauth2":
            resolved_type = "oauth2"
        elif "token" in scheme_name.lower() or "bearer" in scheme_name.lower():
            resolved_type = "bearer"

        return AuthInfo(
            type=resolved_type,
            scopes=scopes,
            header_name=header_name or ("Authorization" if resolved_type in ["bearer", "basic"] else None),
            location=location,
            description=scheme_def.get("description"),
        )

    def build_nodes(self, normalized_spec: Dict[str, Any], base_metadata: Dict[str, Any]) -> List[EndpointNode]:
        """Builds all EndpointNodes from the normalized OpenAPI specification."""
        nodes: List[EndpointNode] = []
        paths = normalized_spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_params = path_item.get("parameters", [])

            for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue

                op_id = self.generate_operation_id(method, path, op.get("operationId"))
                service_prefix = self.extract_service_prefix(path)

                # Collect parameters (merge path-level and operation-level)
                combined_params: List[ParameterModel] = []
                seen_params = set()

                for raw_param in op.get("parameters", []) + path_params:
                    if not isinstance(raw_param, dict) or "name" not in raw_param:
                        continue
                    p_name = raw_param["name"]
                    p_loc = raw_param.get("in", "query")
                    param_key = (p_name, p_loc)
                    if param_key in seen_params:
                        continue
                    seen_params.add(param_key)

                    p_schema = raw_param.get("schema", {})
                    combined_params.append(
                        ParameterModel(
                            name=p_name,
                            location=p_loc,
                            required=raw_param.get("required", p_loc == "path"),
                            schema_type=p_schema.get("type", "string") if isinstance(p_schema, dict) else "string",
                            schema_raw=p_schema if isinstance(p_schema, dict) else {},
                            description=raw_param.get("description", ""),
                        )
                    )

                # Request body
                req_body_schema = None
                req_body = op.get("requestBody")
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    if "application/json" in content:
                        req_body_schema = content["application/json"].get("schema")
                    elif content:
                        first_content = next(iter(content.values()))
                        if isinstance(first_content, dict):
                            req_body_schema = first_content.get("schema")

                # Responses
                responses = op.get("responses", {})

                # Auth
                auth = self.extract_auth_info(op, normalized_spec)

                node_metadata = dict(base_metadata)
                # Propagate any tags or OWASP markers
                raw_tags = op.get("tags", [])
                if raw_tags:
                    node_metadata["raw_tags"] = raw_tags
                    for t in raw_tags:
                        if isinstance(t, str) and ("API" in t or "owasp" in t.lower()):
                            node_metadata["owasp_category"] = t

                node = EndpointNode(
                    id=op_id,
                    method=method.upper(),
                    path=path,
                    summary=op.get("summary", ""),
                    description=op.get("description", ""),
                    parameters=combined_params,
                    request_body_schema=req_body_schema,
                    response_schemas=responses,
                    auth=auth,
                    attack_surface_tags=[],
                    service_prefix=service_prefix,
                    metadata=node_metadata,
                )
                nodes.append(node)

        # Tag nodes using the static rule engine
        return AttackSurfaceTagger.tag_nodes(nodes)

    def infer_edges(self, nodes: List[EndpointNode], normalized_spec: Dict[str, Any]) -> List[EndpointEdge]:
        """
        Infers call-order / dependency edges using 3 signals:
          (a) OpenAPI Links
          (b) Parameter matching (response field -> input param)
          (c) Shared schema fields
        """
        edges: List[EndpointEdge] = []
        node_map = {n.id: n for n in nodes}

        # 1. Signal A: OpenAPI links objects
        edges.extend(self._infer_links_edges(nodes, normalized_spec))

        # 2. Precompute output fields and input fields for all nodes
        node_outputs: Dict[str, Set[str]] = {}
        node_inputs: Dict[str, Set[str]] = {}

        for node in nodes:
            # Output properties from successful responses (2xx)
            out_props: Set[str] = set()
            for code, resp in node.response_schemas.items():
                if str(code).startswith("2"):
                    schema = resp.get("schema") or (
                        resp.get("content", {}).get("application/json", {}).get("schema")
                    )
                    out_props.update(SpecNormalizer.extract_property_names(schema))
            
            # Infer common output fields from endpoint semantics if schema omitted
            path_lower = node.path.lower()
            if "token" in path_lower or "login" in path_lower or "auth" in path_lower:
                out_props.update({"token", "jwt", "service_token", "access_token", "user_id"})
            if "users" in path_lower or "profile" in path_lower:
                out_props.update({"user_id", "id", "doc_id", "tenant_id", "email"})

            node_outputs[node.id] = out_props

            # Input fields: path params, query params, headers, and request body schema
            in_fields: Set[str] = {p.name.lower() for p in node.parameters}
            if node.request_body_schema:
                in_fields.update(SpecNormalizer.extract_property_names(node.request_body_schema))
            node_inputs[node.id] = in_fields

        # Common aliasing mapping
        aliases = {
            "id": {"user_id", "userid", "account_id", "doc_id", "document_id"},
            "user_id": {"id", "userid"},
            "doc_id": {"id", "document_id"},
            "token": {"service_token", "access_token", "bearer_token", "auth_token"},
            "service_token": {"token", "access_token"},
        }

        # 2 & 3: Iterate all node pairs (Node A -> Node B)
        seen_edges = set()
        for edge in edges:
            seen_edges.add((edge.from_node, edge.to_node, edge.field))

        for a in nodes:
            a_outs = node_outputs[a.id]
            if not a_outs:
                continue

            for b in nodes:
                if a.id == b.id:
                    continue

                b_ins = node_inputs[b.id]

                # Check Signal B: Producer-Consumer Parameter Matching
                for out_f in a_outs:
                    matched = False
                    alias_matched = False
                    matched_field = out_f

                    if out_f in b_ins:
                        matched = True
                    else:
                        # Check aliases
                        alias_set = aliases.get(out_f, set())
                        for alias in alias_set:
                            if alias in b_ins:
                                alias_matched = True
                                matched_field = f"{out_f}->{alias}"
                                break

                    if matched or alias_matched:
                        edge_key = (a.id, b.id, matched_field)
                        if edge_key not in seen_edges:
                            seen_edges.add(edge_key)
                            conf = 0.85 if matched else 0.75
                            # Cross-service bonus: chaining across distinct services
                            is_cross = a.service_prefix != b.service_prefix
                            edges.append(
                                EndpointEdge(
                                    from_node=a.id,
                                    to_node=b.id,
                                    relation="produces_param_consumed_by",
                                    field=matched_field,
                                    confidence=conf,
                                    metadata={
                                        "cross_service": is_cross,
                                        "producer_service": a.service_prefix,
                                        "consumer_service": b.service_prefix,
                                    },
                                )
                            )

                # Check Signal C: Shared Schema Field Names Across Bodies
                if a.request_body_schema and b.request_body_schema:
                    a_body_props = SpecNormalizer.extract_property_names(a.request_body_schema)
                    b_body_props = SpecNormalizer.extract_property_names(b.request_body_schema)
                    shared_props = a_body_props.intersection(b_body_props)
                    
                    # Focus on specific identifier keys
                    domain_keys = {"doc_id", "document_id", "user_id", "account_id", "tenant_id", "session_id"}
                    matching_keys = shared_props.intersection(domain_keys)
                    for key in matching_keys:
                        edge_key = (a.id, b.id, key)
                        if edge_key not in seen_edges:
                            seen_edges.add(edge_key)
                            edges.append(
                                EndpointEdge(
                                    from_node=a.id,
                                    to_node=b.id,
                                    relation="shared_schema_field",
                                    field=key,
                                    confidence=0.68,
                                    metadata={"cross_service": a.service_prefix != b.service_prefix},
                                )
                            )

        # Sort edges by from_node, to_node, and confidence descending
        edges.sort(key=lambda e: (e.from_node, e.to_node, -e.confidence))
        return edges

    def _infer_links_edges(self, nodes: List[EndpointNode], spec: Dict[str, Any]) -> List[EndpointEdge]:
        """Extracts explicit OpenAPI link definitions."""
        edges: List[EndpointEdge] = []
        op_id_to_node = {n.id: n for n in nodes}
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if not isinstance(op, dict):
                    continue
                source_op_id = self.generate_operation_id(method, path, op.get("operationId"))
                responses = op.get("responses", {})
                for resp_code, resp_obj in responses.items():
                    if isinstance(resp_obj, dict) and "links" in resp_obj:
                        links = resp_obj["links"]
                        for link_name, link_obj in links.items():
                            target_op_id = link_obj.get("operationId")
                            if target_op_id:
                                clean_target = f"op_{target_op_id.lower()}"
                                edges.append(
                                    EndpointEdge(
                                        from_node=source_op_id,
                                        to_node=clean_target,
                                        relation="openapi_link",
                                        field=link_name,
                                        confidence=0.95,
                                        metadata={"explicit_link": True},
                                    )
                                )
        # Sort edges by from_node, to_node, and confidence descending
        edges.sort(key=lambda e: (e.from_node, e.to_node, -e.confidence))
        return edges

    def build_graph(
        self, target_id: str, spec_hash: str, normalized_spec: Dict[str, Any], metadata: Dict[str, Any]
    ) -> EndpointGraph:
        """Constructs and returns the full EndpointGraph."""
        nodes = self.build_nodes(normalized_spec, metadata)
        edges = self.infer_edges(nodes, normalized_spec)

        # Populate internal NetworkX DiGraph
        self.nx_graph.clear()
        for node in nodes:
            self.nx_graph.add_node(node.id, data=node.model_dump())
        for edge in edges:
            self.nx_graph.add_edge(
                edge.from_node, edge.to_node, relation=edge.relation, field=edge.field, confidence=edge.confidence
            )

        graph_metrics = {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "cross_service_edges": sum(1 for e in edges if e.metadata.get("cross_service", False)),
            "density": nx.density(self.nx_graph) if len(nodes) > 1 else 0.0,
        }
        metadata["graph_metrics"] = graph_metrics

        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return EndpointGraph(
            target_id=target_id,
            graph_id=f"graph_{target_id}_{spec_hash[:8]}",
            spec_hash=spec_hash,
            nodes=nodes,
            edges=edges,
            created_at=now,
            updated_at=now,
            metadata=metadata,
        )
