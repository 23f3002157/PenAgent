import ipaddress
import re
from urllib.parse import urlsplit, unquote


class Rejected(ValueError):
    """A controlled policy rejection with a non-sensitive reason code."""


def origin(url: str) -> tuple[str, str, int]:
    try:
        u = urlsplit(url)
        if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password or u.fragment:
            raise ValueError()
        if any(ord(c) <= 32 for c in url) or "\\" in url:
            raise ValueError()
        ip = ipaddress.ip_address(u.hostname)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or getattr(ip, "ipv4_mapped", None):
            raise ValueError()
        # Explicit special-purpose metadata endpoints, including Azure wire server.
        if str(ip) in {"168.63.129.16", "100.100.100.200"}:
            raise ValueError()
        return u.scheme, str(ip), u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise Rejected("invalid_or_unsafe_origin") from None


def enforce_url(url: str, target) -> None:
    if origin(url) != origin(target.base_url):
        raise Rejected("unauthorized_destination")
    path = urlsplit(url).path
    decoded = unquote(unquote(path))
    if any(p in {".", ".."} for p in decoded.split("/")) or "\\" in decoded or decoded.startswith("//"):
        raise Rejected("unsafe_path")


def enforce_operation(node, rule, requires_approval: bool = False) -> None:
    if not rule or node.method != rule.method or node.path != rule.path:
        raise Rejected("operation_not_authorized_or_schema_drift")
    semantic = " ".join([node.path, node.summary or "", node.description or ""]).lower()
    dangerous = re.search(r"delete|purge|reset|destroy|truncate|transfer|payment|charge|purchase|withdraw|shutdown|reboot|drop\b|corrupt", semantic)
    if requires_approval or dangerous or rule.risk != "safe" or node.method == "DELETE":
        raise Rejected("approval_required_component5_unavailable")
    # Safe POST/search etc. requires explicit operator rule; all other ops also
    # require a matching rule. Verb alone is never evidence of authorization.


def redact(value):
    """Public/model representation: keep shape and evidence hashes, not contents."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if re.search(r"token|secret|password|cookie|authorization|key|email|phone|ssn|credential", k, re.I) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
