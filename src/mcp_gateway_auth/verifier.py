"""Verification of internal JWTs issued by MCP Gateway (see docs/internal-jwt.md)."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWK

log = logging.getLogger(__name__)

DEFAULT_JWKS_URL = "http://mcp-gateway:9000/jwks.json"
ISSUER = "mcp-gateway"
ALGORITHM = "EdDSA"
LEEWAY_SECONDS = 10


class AuthError(Exception):
    """Base class for all verification failures."""


class MissingToken(AuthError):
    pass


class InvalidToken(AuthError):
    """Malformed token, bad signature or wrong claims."""


class TokenExpired(InvalidToken):
    pass


class InvalidAudience(InvalidToken):
    pass


class InvalidIssuer(InvalidToken):
    pass


class UnknownKey(InvalidToken):
    """Signed with a key the gateway does not publish."""


class JWKSUnavailable(AuthError):
    """The gateway JWKS could not be loaded and no cached keys exist."""


@dataclass(frozen=True, slots=True)
class Principal:
    """The employee behind a request, as vouched for by the gateway.

    Fields carry Keycloak's claim names:
      sub                 stable employee id (UUID) — use it as the user key
      preferred_username  Keycloak login; may change, do not use as a key
      name                full name for display ("Алиса Иванова"); given_name / family_name — parts
      email               work e-mail from Keycloak; may be absent
      roles               Keycloak realm roles (mcp-*, default-roles-kh, ...)
      groups              Keycloak group memberships as full paths ("/Разработка/AI") —
                          the company org structure, not CRM/1C groups
      azp                 id of the MCP client (Claude, Cursor, ...)
    """

    sub: str
    preferred_username: str | None
    roles: frozenset[str]
    azp: str | None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email: str | None = None
    groups: frozenset[str] = frozenset()

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def in_group(self, path: str) -> bool:
        """Member of the group `path` (e.g. "/Sales") or of any of its subgroups."""
        path = path.rstrip("/")
        return any(g == path or g.startswith(path + "/") for g in self.groups)

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> Principal:
        return cls(
            sub=str(claims.get("sub") or ""),
            preferred_username=_str(claims.get("preferred_username")),
            roles=_strings(claims.get("roles")),
            azp=_str(claims.get("azp")),
            name=_str(claims.get("name")),
            given_name=_str(claims.get("given_name")),
            family_name=_str(claims.get("family_name")),
            email=_str(claims.get("email")),
            groups=_strings(claims.get("groups")),
        )

    def to_claims(self) -> dict[str, Any]:
        return {
            "sub": self.sub,
            "preferred_username": self.preferred_username,
            "name": self.name,
            "given_name": self.given_name,
            "family_name": self.family_name,
            "email": self.email,
            "roles": sorted(self.roles),
            "groups": sorted(self.groups),
            "azp": self.azp,
        }


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        return frozenset()
    return frozenset(v for v in value if isinstance(v, str))


class JWKSCache:
    """Gateway public keys: cached, refreshed periodically and when an unknown kid appears."""

    def __init__(
        self,
        url: str,
        *,
        max_age: float = 600.0,
        unknown_kid_min_interval: float = 5.0,
        timeout: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
        http: httpx.Client | None = None,
    ) -> None:
        self.url = url
        self._max_age = max_age
        self._min_interval = unknown_kid_min_interval
        self._clock = clock
        self._http = http or httpx.Client(timeout=timeout, trust_env=False)
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = threading.Lock()

    def cached(self, kid: str) -> PyJWK | None:
        """Key from cache without any network access; None if a fetch is needed."""
        if self._fetched_at is None or self._clock() - self._fetched_at > self._max_age:
            return None
        return self._keys.get(kid)

    def get(self, kid: str) -> PyJWK:
        key = self.cached(kid)
        if key is not None:
            return key
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at > self._max_age
            may_retry = self._attempted_at is None or now - self._attempted_at >= self._min_interval
            if (stale or kid not in self._keys) and may_retry:
                self._fetch()
            key = self._keys.get(kid)
        if key is not None:
            return key
        if self._fetched_at is None:
            raise JWKSUnavailable(f"cannot load gateway JWKS from {self.url}")
        raise UnknownKey(f"unknown key id {kid!r}")

    def _fetch(self) -> None:
        self._attempted_at = self._clock()
        try:
            resp = self._http.get(self.url)
            resp.raise_for_status()
            doc = resp.json()
            keys = {}
            for data in doc.get("keys", []):
                if data.get("kty") == "OKP" and data.get("crv") == "Ed25519" and "kid" in data:
                    keys[data["kid"]] = PyJWK(data, algorithm=ALGORITHM)
        except (httpx.HTTPError, ValueError, AttributeError, jwt.PyJWTError) as exc:
            log.warning("gateway JWKS fetch failed: %r", exc)
            return
        self._keys = keys
        self._fetched_at = self._attempted_at


class GatewayVerifier:
    def __init__(self, jwks_url: str | None = None, *, jwks: JWKSCache | None = None) -> None:
        url = jwks_url or os.environ.get("MCP_GATEWAY_JWKS_URL", DEFAULT_JWKS_URL)
        self.jwks = jwks or JWKSCache(url)

    def verify(self, token: str, audience: str) -> Principal:
        """Check the internal JWT. May block on a JWKS fetch; see `averify` for async code."""
        return self._verify(token, audience, self.jwks.get)

    async def averify(self, token: str, audience: str) -> Principal:
        try:
            return self._verify(token, audience, self._cached_or_raise)
        except _NeedsFetch:
            return await asyncio.to_thread(self.verify, token, audience)

    def _cached_or_raise(self, kid: str) -> PyJWK:
        key = self.jwks.cached(kid)
        if key is None:
            raise _NeedsFetch
        return key

    def _verify(self, token: str, audience: str, key_for: Callable[[str], PyJWK]) -> Principal:
        if not token:
            raise MissingToken("no token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidToken("malformed token") from exc
        if header.get("alg") != ALGORITHM:
            raise InvalidToken(f"algorithm not allowed: {header.get('alg')!r}")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("token has no kid")
        key = key_for(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=ISSUER,
                leeway=LEEWAY_SECONDS,
                options={"require": ["iss", "aud", "sub", "exp", "iat"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpired("token expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise InvalidAudience("token issued for another service") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidIssuer("token not issued by mcp-gateway") from exc
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"invalid token: {exc.__class__.__name__}") from exc
        if claims.get("aud") != audience:
            # PyJWT accepts a list containing the audience; the gateway always sends one string.
            raise InvalidAudience("token issued for another service")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise InvalidToken("token has no sub")
        return Principal.from_claims(claims)


class _NeedsFetch(Exception):
    pass


_default: GatewayVerifier | None = None
_default_lock = threading.Lock()


def default_verifier() -> GatewayVerifier:
    """Process-wide verifier using $MCP_GATEWAY_JWKS_URL (default http://mcp-gateway:9000/jwks.json)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = GatewayVerifier()
        return _default


def verify(token: str, audience: str) -> Principal:
    """Verify an internal JWT for `audience` (your service name) and return who is calling."""
    return default_verifier().verify(token, audience)
