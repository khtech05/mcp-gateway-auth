"""Generic ASGI middleware for MCP servers not built on FastMCP."""

from __future__ import annotations

import contextvars
import json
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from .verifier import AuthError, GatewayVerifier, JWKSUnavailable, Principal, default_verifier

log = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
ASGIApp = Callable[
    [Scope, Callable[[], Awaitable[Any]], Callable[[Any], Awaitable[None]]], Awaitable[None]
]

SCOPE_KEY = "mcp_gateway_principal"
principal_var: contextvars.ContextVar[Principal | None] = contextvars.ContextVar(
    "mcp_gateway_principal", default=None
)


class GatewayAuthMiddleware:
    """Rejects HTTP requests without a valid internal JWT for `audience`.

    The caller is stored in `scope["state"]["mcp_gateway_principal"]` and in a context
    variable read by `current_principal()`.
    """

    def __init__(
        self,
        app: ASGIApp,
        audience: str,
        verifier: GatewayVerifier | None = None,
        exempt_paths: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.audience = audience
        self.verifier = verifier
        self.exempt_paths = exempt_paths

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["path"] in self.exempt_paths:
            await self.app(scope, receive, send)
            return
        token = None
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                scheme, _, rest = value.decode("latin-1").partition(" ")
                if scheme.lower() == "bearer":
                    token = rest.strip()
                break
        verifier = self.verifier or default_verifier()
        try:
            principal = await verifier.averify(token or "", self.audience)
        except JWKSUnavailable as exc:
            log.error("cannot verify internal JWT: %s", exc)
            await _deny(send, 503, "gateway keys unavailable")
            return
        except AuthError as exc:
            log.warning("internal JWT rejected: %s", exc)
            await _deny(send, 401, "invalid or missing gateway token")
            return
        scope.setdefault("state", {})[SCOPE_KEY] = principal
        reset = principal_var.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            principal_var.reset(reset)


async def _deny(send: Any, status: int, description: str) -> None:
    body = json.dumps({"error": "unauthorized", "error_description": description}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
