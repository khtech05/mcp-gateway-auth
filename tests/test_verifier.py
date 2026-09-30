from __future__ import annotations

import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp_gateway_auth import (
    GatewayVerifier,
    InvalidAudience,
    InvalidIssuer,
    InvalidToken,
    JWKSCache,
    JWKSUnavailable,
    MissingToken,
    TokenExpired,
    UnknownKey,
)

from mcp_gateway.keycloak import KeycloakIdentity
from mcp_gateway.signing import InternalTokenIssuer, KeyRing, generate_key_file

IDENTITY = KeycloakIdentity(
    sub="user-1",
    preferred_username="alice",
    azp="claude",
    roles=("mcp-demo",),
    name="Алиса Иванова",
    given_name="Алиса",
    family_name="Иванова",
    email="alice@kh-tech.ru",
    groups=("/Разработка/AI", "/Продажи"),
)


class GatewayJWKS:
    """Serves the JWKS of whatever keys are currently in `directory`."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.requests = 0
        self.available = True

    def handler(self, request: httpx.Request) -> httpx.Response:
        if not self.available:
            raise httpx.ConnectError("down", request=request)
        self.requests += 1
        return httpx.Response(200, json=KeyRing.load(self.directory).jwks())


def make(tmp_path: Path, **cache_kwargs: object) -> tuple[GatewayJWKS, GatewayVerifier, Path]:
    keys = tmp_path / "keys"
    generate_key_file(keys, "2026-01-01")
    server = GatewayJWKS(keys)
    cache = JWKSCache(
        "http://gw/jwks.json",
        http=httpx.Client(transport=httpx.MockTransport(server.handler)),
        **cache_kwargs,
    )  # type: ignore[arg-type]
    return server, GatewayVerifier(jwks=cache), keys


def issue(keys: Path, audience: str = "demo", **kw: object) -> str:
    return InternalTokenIssuer(KeyRing.load(keys), **kw).issue(IDENTITY, audience)  # type: ignore[arg-type]


def test_valid_token(tmp_path: Path) -> None:
    _, verifier, keys = make(tmp_path)
    p = verifier.verify(issue(keys), "demo")
    assert p.sub == "user-1" and p.preferred_username == "alice"
    assert p.roles == frozenset({"mcp-demo"}) and p.azp == "claude"
    assert p.has_role("mcp-demo")
    assert p.name == "Алиса Иванова"
    assert (p.given_name, p.family_name) == ("Алиса", "Иванова")
    assert p.email == "alice@kh-tech.ru"
    assert p.groups == frozenset({"/Разработка/AI", "/Продажи"})


def test_in_group_includes_subgroups() -> None:
    from mcp_gateway_auth import Principal

    p = Principal.from_claims({"sub": "x", "groups": ["/Разработка/AI", "/Продажи"]})
    assert p.in_group("/Разработка") and p.in_group("/Разработка/AI") and p.in_group("/Продажи/")
    assert not p.in_group("/Разработка/AI/Прочее")
    assert not p.in_group("/Разраб")  # a prefix of a name is not a parent group
    assert p.name is None and p.preferred_username is None


def test_other_audience_rejected(tmp_path: Path) -> None:
    """Criterion 5: a token for another service is refused."""
    _, verifier, keys = make(tmp_path)
    with pytest.raises(InvalidAudience):
        verifier.verify(issue(keys, audience="reghub"), "demo")


def test_missing_and_garbage(tmp_path: Path) -> None:
    _, verifier, _ = make(tmp_path)
    with pytest.raises(MissingToken):
        verifier.verify("", "demo")
    with pytest.raises(InvalidToken):
        verifier.verify("abc", "demo")


def test_expired_with_leeway(tmp_path: Path) -> None:
    _, verifier, keys = make(tmp_path)
    past = time.time() - 65
    verifier.verify(issue(keys, clock=lambda: past), "demo")  # exp 5 s ago, leeway 10 s
    with pytest.raises(TokenExpired):
        verifier.verify(issue(keys, clock=lambda: time.time() - 80), "demo")


def test_foreign_signer_and_issuer(tmp_path: Path) -> None:
    _, verifier, _ = make(tmp_path)
    now = int(time.time())
    claims = {"iss": "mcp-gateway", "aud": "demo", "sub": "x", "iat": now, "exp": now + 60}
    forged = jwt.encode(
        claims, Ed25519PrivateKey.generate(), algorithm="EdDSA", headers={"kid": "2026-01-01"}
    )
    with pytest.raises(InvalidToken):
        verifier.verify(forged, "demo")
    with pytest.raises(InvalidToken, match="algorithm"):
        verifier.verify(
            jwt.encode(claims, "k" * 32, algorithm="HS256", headers={"kid": "2026-01-01"}), "demo"
        )
    real = (tmp_path / "keys" / "2026-01-01.pem").read_bytes()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with pytest.raises(InvalidIssuer):
        verifier.verify(
            jwt.encode(
                {**claims, "iss": "someone"},
                load_pem_private_key(real, None),
                algorithm="EdDSA",
                headers={"kid": "2026-01-01"},
            ),
            "demo",
        )


def test_key_rotation_without_errors(tmp_path: Path) -> None:
    """Criterion 8: add key -> restart gateway -> old key removed later."""
    server, verifier, keys = make(tmp_path, unknown_kid_min_interval=0.0)
    verifier.verify(issue(keys), "demo")  # caches old key
    generate_key_file(keys, "2026-10-01")  # new key, gateway restarted
    token = issue(keys)
    assert jwt.get_unverified_header(token)["kid"] == "2026-10-01"
    assert verifier.verify(token, "demo").sub == "user-1"  # unknown kid -> refetch
    (keys / "2026-01-01.pem").unlink()  # old key removed
    assert verifier.verify(issue(keys), "demo").sub == "user-1"
    assert server.requests == 2


def test_unknown_kid_refetch_throttled(tmp_path: Path) -> None:
    server, verifier, keys = make(tmp_path)
    verifier.verify(issue(keys), "demo")
    now = int(time.time())
    bogus = jwt.encode(
        {"sub": "x", "iat": now, "exp": now + 60},
        Ed25519PrivateKey.generate(),
        algorithm="EdDSA",
        headers={"kid": "nope"},
    )
    for _ in range(5):
        with pytest.raises(UnknownKey):
            verifier.verify(bogus, "demo")
    assert server.requests == 1  # the first failed lookup is within the 5 s throttle window


def test_gateway_down(tmp_path: Path) -> None:
    server, verifier, keys = make(tmp_path, max_age=0.0)
    token = issue(keys)
    server.available = False
    with pytest.raises(JWKSUnavailable):
        verifier.verify(token, "demo")
    server.available = True
    verifier.jwks._attempted_at = None
    verifier.verify(token, "demo")
    server.available = False
    verifier.jwks._attempted_at = None
    assert verifier.verify(token, "demo").sub == "user-1"  # stale keys still used


@pytest.mark.anyio
async def test_averify(tmp_path: Path) -> None:
    _, verifier, keys = make(tmp_path)
    assert (await verifier.averify(issue(keys), "demo")).sub == "user-1"
    assert (await verifier.averify(issue(keys), "demo")).sub == "user-1"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
