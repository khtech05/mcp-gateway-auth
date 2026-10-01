"""Verification of MCP Gateway internal JWTs — the only auth code an MCP server needs.

FastMCP:
    from mcp_gateway_auth import current_principal
    from mcp_gateway_auth.fastmcp import GatewayAuth

    mcp = FastMCP("dochub", auth=GatewayAuth(audience="dochub"))

    @mcp.tool
    def search(query: str) -> str:
        user = current_principal()   # Principal(sub, preferred_username, roles, azp)

Anything else:
    principal = verify(token, audience="dochub")
"""

from __future__ import annotations

from .asgi import GatewayAuthMiddleware, principal_var
from .verifier import (
    AuthError,
    GatewayVerifier,
    InvalidAudience,
    InvalidIssuer,
    InvalidToken,
    JWKSCache,
    JWKSUnavailable,
    MissingToken,
    Principal,
    TokenExpired,
    UnknownKey,
    verify,
)

__all__ = [
    "AuthError",
    "GatewayAuthMiddleware",
    "GatewayVerifier",
    "InvalidAudience",
    "InvalidIssuer",
    "InvalidToken",
    "JWKSCache",
    "JWKSUnavailable",
    "MissingToken",
    "NotAuthenticated",
    "Principal",
    "TokenExpired",
    "UnknownKey",
    "current_principal",
    "verify",
]


class NotAuthenticated(AuthError):
    """current_principal() called outside an authenticated request."""


def current_principal() -> Principal:
    """The employee behind the current MCP request."""
    principal = principal_var.get()
    if principal is not None:
        return principal
    try:
        from fastmcp.server.dependencies import get_access_token

        from .fastmcp import principal_from_access_token
    except ImportError:
        pass
    else:
        token = get_access_token()
        if token is not None:
            return principal_from_access_token(token)
    raise NotAuthenticated("no authenticated gateway principal in this context")
