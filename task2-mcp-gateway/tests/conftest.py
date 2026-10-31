"""Shared fixtures: signing keys are generated per test session, never committed."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ISSUER = "https://idp.test.local/"
AUDIENCE = "quilr-mcp-gateway"


def _pem_public(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def other_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_public_pem(rsa_key: rsa.RSAPrivateKey) -> bytes:
    return _pem_public(rsa_key)


@pytest.fixture(scope="session")
def ec_public_pem(ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    return _pem_public(ec_key)


Minter = Callable[..., str]


@pytest.fixture(scope="session")
def mint(rsa_key: rsa.RSAPrivateKey) -> Minter:
    """Mint an RS256 token; any claim can be overridden or removed (value=None)."""

    def _mint(
        *,
        key: Any = None,
        algorithm: str = "RS256",
        headers: dict[str, Any] | None = None,
        **claims: Any,
    ) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "role": "viewer",
            "iat": now,
            "exp": now + 300,
        }
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not None}
        return jwt.encode(payload, key or rsa_key, algorithm=algorithm, headers=headers)

    return _mint
