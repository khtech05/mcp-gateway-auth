"""Поддельный шлюз: ключи, JWKS и выпуск пропусков — без кода самого шлюза.

Тесты библиотеки проверяют только её сторону контракта (docs/internal-jwt.md шлюза), поэтому
пропуска здесь выпускает этот минимальный двойник. Что настоящий шлюз выпускает ровно такие
токены, проверяет сквозной тест в его репозитории (`tests/test_e2e_demo.py`).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TOKEN_TTL_S = 60


@dataclass(frozen=True)
class Identity:
    """Сотрудник, как его описывает шлюз в пропуске."""

    sub: str = "user-1"
    preferred_username: str = "alice"
    azp: str = "claude"
    roles: tuple[str, ...] = ("mcp-demo",)
    name: str = "Алиса Иванова"
    given_name: str = "Алиса"
    family_name: str = "Иванова"
    email: str = "alice@kh-tech.ru"
    groups: tuple[str, ...] = ("/Разработка/AI", "/Продажи")


IDENTITY = Identity()


def generate_key_file(directory: Path, kid: str) -> Path:
    """Ключ подписи шлюза: PEM с именем `<kid>.pem`, как в его каталоге ключей."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{kid}.pem"
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def _keys(directory: Path) -> dict[str, Ed25519PrivateKey]:
    return {
        path.stem: serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[misc]
        for path in sorted(directory.glob("*.pem"))
    }


def jwks(directory: Path) -> dict:
    """JWKS шлюза: открытые части всех ключей из каталога."""
    keys = []
    for kid, key in _keys(directory).items():
        jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": kid, "use": "sig", "alg": "EdDSA"})
        keys.append(jwk)
    return {"keys": keys}


def issue(
    directory: Path,
    audience: str = "demo",
    *,
    identity: Identity = IDENTITY,
    clock: Callable[[], float] = time.time,
    issuer: str = "mcp-gateway",
) -> str:
    """Пропуск: подписывается самым новым ключом каталога, живёт 60 с."""
    kid, key = max(_keys(directory).items())
    now = int(clock())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": identity.sub,
        "preferred_username": identity.preferred_username,
        "name": identity.name,
        "given_name": identity.given_name,
        "family_name": identity.family_name,
        "email": identity.email,
        "roles": list(identity.roles),
        "groups": list(identity.groups),
        "azp": identity.azp,
        "iat": now,
        "exp": now + TOKEN_TTL_S,
    }
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid})
