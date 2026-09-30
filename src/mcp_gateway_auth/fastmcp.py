"""FastMCP integration: `FastMCP(..., auth=GatewayAuth(audience="reghub"))`."""

from __future__ import annotations

import logging

from fastmcp.server.auth import AccessToken, TokenVerifier

from .verifier import AuthError, GatewayVerifier, Principal, default_verifier

log = logging.getLogger(__name__)


class GatewayAuth(TokenVerifier):
    """Accepts only internal JWTs issued by MCP Gateway for `audience`."""

    def __init__(self, audience: str, verifier: GatewayVerifier | None = None) -> None:
        super().__init__()
        self.audience = audience
        self._verifier = verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        verifier = self._verifier or default_verifier()
        try:
            principal = await verifier.averify(token, self.audience)
        except AuthError as exc:
            log.warning("internal JWT rejected: %s", exc)
            return None
        return AccessToken(
            token=token,
            client_id=principal.azp or "unknown",
            scopes=[],
            subject=principal.sub,
            claims=principal.to_claims(),
        )


def principal_from_access_token(token: AccessToken) -> Principal:
    claims = dict(token.claims or {})
    claims.setdefault("sub", token.subject)
    return Principal.from_claims(claims)
