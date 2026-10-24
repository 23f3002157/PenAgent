"""Bounded control-plane HTTP; never used to send target probes."""
import asyncio
import json
import httpx
from penagent_common.policy import Rejected


async def service_call(settings, method, base, path, *, payload=None, correlation_id=None):
    if not base:
        raise Rejected("upstream_not_configured")
    headers = {"Authorization": f"Bearer {settings.service_token}"}
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id
    try:
        async with asyncio.timeout(settings.service_timeout):
            async with httpx.AsyncClient(timeout=settings.service_timeout, trust_env=False, follow_redirects=False) as client:
                async with client.stream(method, base.rstrip("/") + path, headers=headers, json=payload) as response:
                    if response.status_code == 204:
                        return None
                    if not 200 <= response.status_code < 300:
                        raise Rejected(f"upstream_http_{response.status_code}")
                    data = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        if len(data) + len(chunk) > max(settings.max_response_size, 1048576):
                            raise Rejected("upstream_response_too_large")
                        data.extend(chunk)
                    return json.loads(data)
    except (httpx.HTTPError, TimeoutError):
        raise Rejected("upstream_unavailable") from None
    except (ValueError, RecursionError):
        raise Rejected("upstream_invalid_json") from None
