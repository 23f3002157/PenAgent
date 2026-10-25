import hmac
from uuid import uuid4

from fastapi import Header, HTTPException, Request
from fastapi.responses import JSONResponse
from penagent_common.policy import Rejected


class BodyLimit:
    """Bound untrusted API JSON before framework deserialization."""
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.limit:
                response = JSONResponse(status_code=413, content={"detail": "request_too_large"})
                return await response(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        consumed = False
        async def replay():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        return await self.app(scope, replay, send)


def install_errors(app):
    @app.exception_handler(Rejected)
    async def rejection(request: Request, error: Rejected):
        code = str(error)
        status = 404 if code in {"audit_not_found", "probe_not_found"} else 503 if code.startswith("upstream") else 409
        return JSONResponse(status_code=status, content={"detail": code})


def owner_dependency(settings):
    async def owner(authorization: str = Header(default="")):
        token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        for subject, configured in settings.api_tokens.items():
            if token and configured and hmac.compare_digest(token, configured):
                return subject
        raise HTTPException(status_code=401, detail="invalid_api_token")
    return owner


def machine_dependency(settings):
    async def machine(authorization: str = Header(default="")):
        if not settings.service_token or not hmac.compare_digest(authorization, "Bearer " + settings.service_token):
            raise HTTPException(status_code=401, detail="invalid_service_token")
        return True
    return machine


def correlation(value: str | None) -> str:
    import re
    return value if value and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value) else uuid4().hex
