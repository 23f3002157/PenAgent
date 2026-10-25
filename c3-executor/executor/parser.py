import hashlib
import json
from typing import Any

from jsonschema import Draft7Validator
from penagent_common.models import Parsed


def response_schema(node, status: int) -> dict:
    response = node.response_schemas.get(str(status), node.response_schemas.get("default", {}))
    return response.get("schema") or response.get("content", {}).get("application/json", {}).get("schema", {})


def parse_response(body: bytes, content_type: str, node, status: int, credential_fields: list[str]) -> Parsed:
    digest = hashlib.sha256(body).hexdigest()
    if not body:
        return Parsed(kind="empty", body_sha256=digest)
    text = body.decode("utf-8", errors="replace")
    if "json" not in content_type.lower():
        return Parsed(kind="text" if content_type.startswith("text/") else "binary", data=text if content_type.startswith("text/") else None, body_sha256=digest)
    try:
        data = json.loads(text, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        return Parsed(kind="malformed", parse_error="invalid_json", body_sha256=digest)
    schema = response_schema(node, status)
    artifacts: dict[str, Any] = {}
    credentials: list[str] = []

    def walk(value, definition, prefix="", depth=0):
        if depth > 20:
            return
        if not isinstance(value, dict) or not isinstance(definition, dict):
            return
        for name, field_schema in definition.get("properties", {}).items():
            if name not in value:
                continue
            item = value[name]
            path = f"{prefix}.{name}".strip(".")
            try:
                valid = Draft7Validator(field_schema).is_valid(item)
            except Exception:
                valid = False
            if valid and isinstance(item, (str, int)) and not isinstance(item, bool):
                if name == "id" or name.endswith("_id"):
                    artifacts[path] = item
                if path in credential_fields and isinstance(item, str) and 8 <= len(item) <= 8192 and not any(ord(c) < 33 or ord(c) > 126 for c in item):
                    artifacts[path] = item
                    credentials.append(path)
            walk(item, field_schema, path, depth + 1)

    if 200 <= status < 300:
        walk(data, schema)
    return Parsed(kind="json", data=data, artifacts=artifacts, credential_fields=credentials, body_sha256=digest)
