import copy
import hashlib
import json
from typing import Dict, Any, List, Set, Tuple, Optional
import yaml


class SpecNormalizer:
    """
    Normalizes OpenAPI 3.x and Swagger 2.0 specifications into a unified Internal Representation (IR),
    resolving $ref references and standardizing schema structures.
    """

    def __init__(self, max_deref_depth: int = 15):
        self.max_deref_depth = max_deref_depth

    @staticmethod
    def parse_raw_spec(content: str) -> Dict[str, Any]:
        """Parses raw text content as JSON or YAML."""
        content_clean = content.strip()
        if content_clean.startswith("{") or content_clean.startswith("["):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                pass
        return yaml.safe_load(content)

    @staticmethod
    def compute_spec_hash(raw_spec: Dict[str, Any]) -> str:
        """Computes a deterministic SHA-256 hash of the specification."""
        canonical_json = json.dumps(raw_spec, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def resolve_ref(self, ref_str: str, root_doc: Dict[str, Any], visited: Set[str]) -> Any:
        """Resolves internal JSON pointer $ref like '#/components/schemas/User'."""
        if ref_str in visited:
            # Prevent infinite recursion in cyclical schemas
            return {"type": "object", "description": f"Cyclic ref to {ref_str}"}

        branch_visited = visited.copy()
        branch_visited.add(ref_str)

        if not ref_str.startswith("#/"):
            # External references: return placeholder if cannot resolve locally
            return {"type": "object", "description": f"External ref: {ref_str}"}

        parts = ref_str[2:].split("/")
        curr = root_doc
        for part in parts:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return {"type": "object", "description": f"Unresolved ref: {ref_str}"}

        return self.dereference(curr, root_doc, branch_visited)

    def dereference(self, obj: Any, root_doc: Dict[str, Any], visited: Optional[Set[str]] = None, depth: int = 0) -> Any:
        """Recursively dereferences $ref keys in dicts and lists."""
        if visited is None:
            visited = set()

        if depth > self.max_deref_depth:
            return obj

        if isinstance(obj, dict):
            if "$ref" in obj and isinstance(obj["$ref"], str):
                ref_target = self.resolve_ref(obj["$ref"], root_doc, visited)
                # If target is dict, merge sibling properties with resolved dict
                if isinstance(ref_target, dict):
                    merged = copy.deepcopy(ref_target)
                    for k, v in obj.items():
                        if k != "$ref":
                            merged[k] = self.dereference(v, root_doc, visited.copy(), depth + 1)
                    return merged
                return ref_target

            new_dict = {}
            for k, v in obj.items():
                new_dict[k] = self.dereference(v, root_doc, visited.copy(), depth + 1)
            return new_dict

        elif isinstance(obj, list):
            return [self.dereference(item, root_doc, visited.copy(), depth + 1) for item in obj]

        return obj

    def normalize(self, raw_spec: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        """
        Normalizes Swagger 2.0 or OpenAPI 3.x spec to unified OpenAPI 3.0-compatible IR.
        Returns: (normalized_spec, spec_hash)
        """
        spec_hash = self.compute_spec_hash(raw_spec)
        spec = copy.deepcopy(raw_spec)

        is_swagger_2 = "swagger" in spec and spec.get("swagger", "").startswith("2")
        
        # Ensure components container exists
        if "components" not in spec or not isinstance(spec["components"], dict):
            spec["components"] = {}

        # Coerce Swagger 2.0 to OpenAPI 3.x structures
        if is_swagger_2:
            spec = self._convert_swagger2_to_openapi3(spec)

        # Dereference schemas throughout document
        dereferenced_spec = self.dereference(spec, spec)
        return dereferenced_spec, spec_hash

    def _convert_swagger2_to_openapi3(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Translates Swagger 2.0 fields to OpenAPI 3.0."""
        # 1. Definitions -> components.schemas
        if "definitions" in spec and isinstance(spec["definitions"], dict):
            spec["components"]["schemas"] = spec["definitions"]

        # 2. SecurityDefinitions -> components.securitySchemes
        if "securityDefinitions" in spec and isinstance(spec["securityDefinitions"], dict):
            sec_schemes = {}
            for name, scheme in spec["securityDefinitions"].items():
                scheme_type = scheme.get("type", "")
                if scheme_type == "basic":
                    sec_schemes[name] = {"type": "http", "scheme": "basic"}
                elif scheme_type == "apiKey":
                    sec_schemes[name] = {
                        "type": "apiKey",
                        "name": scheme.get("name", "X-API-KEY"),
                        "in": scheme.get("in", "header"),
                    }
                elif scheme_type == "oauth2":
                    sec_schemes[name] = {
                        "type": "oauth2",
                        "flows": scheme.get("flow", "implicit"),
                    }
                else:
                    sec_schemes[name] = scheme
            spec["components"]["securitySchemes"] = sec_schemes

        # 3. BasePath handling
        base_path = spec.get("basePath", "")
        if base_path and base_path != "/":
            new_paths = {}
            for p, p_item in spec.get("paths", {}).items():
                normalized_p = f"{base_path.rstrip('/')}/{p.lstrip('/')}"
                new_paths[normalized_p] = p_item
            spec["paths"] = new_paths

        # 4. Parameters in body -> requestBody
        for p, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue

                new_params = []
                for param in op.get("parameters", []):
                    if not isinstance(param, dict):
                        continue
                    if param.get("in") == "body":
                        schema = param.get("schema", {})
                        op["requestBody"] = {
                            "required": param.get("required", False),
                            "content": {
                                "application/json": {"schema": schema}
                            }
                        }
                    else:
                        new_params.append(param)
                op["parameters"] = new_params

        spec["openapi"] = "3.0.0"
        return spec

    @staticmethod
    def extract_property_names(schema: Optional[Dict[str, Any]]) -> Set[str]:
        """Extracts all nested property names from a schema dict."""
        props: Set[str] = set()
        if not schema or not isinstance(schema, dict):
            return props

        # Direct properties
        if "properties" in schema and isinstance(schema["properties"], dict):
            for prop_name, prop_def in schema["properties"].items():
                props.add(prop_name.lower())
                props.update(SpecNormalizer.extract_property_names(prop_def))

        # Array items
        if "items" in schema and isinstance(schema["items"], dict):
            props.update(SpecNormalizer.extract_property_names(schema["items"]))

        # Combinators
        for comb in ["allOf", "anyOf", "oneOf"]:
            if comb in schema and isinstance(schema[comb], list):
                for sub in schema[comb]:
                    props.update(SpecNormalizer.extract_property_names(sub))

        return props
