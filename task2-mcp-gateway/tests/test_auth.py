"""Unit tests for Bearer-token verification and role extraction."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from task2_mcp_gateway.auth import AuthError, Principal, Role, TokenVerifier

# Must match the defaults minted by the ``mint`` fixture in conftest.py.
ISSUER = "https://idp.test.local/"
AUDIENCE = "quilr-mcp-gateway"
Minter = Callable[..., str]


@pytest.fixture
def verifier(rsa_public_pem: bytes, ec_public_pem: bytes) -> TokenVerifier:
    return TokenVerifier.from_pem([rsa_public_pem, ec_public_pem], issuer=ISSUER, audience=AUDIENCE)


def _reason(verifier: TokenVerifier, header: str | None) -> str:
    with pytest.raises(AuthError) as exc:
        verifier.verify(header)
    return exc.value.reason


# --- Happy paths ----------------------------------------------------------------


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_valid_token_yields_principal(verifier: TokenVerifier, mint: Minter, role: str) -> None:
    principal = verifier.verify(f"Bearer {mint(role=role, sub='alice')}")
    assert principal == Principal(subject="alice", role=Role(role))


def test_es256_tokens_are_accepted(
    verifier: TokenVerifier, mint: Minter, ec_key: ec.EllipticCurvePrivateKey
) -> None:
    token = mint(key=ec_key, algorithm="ES256", role="admin")
    assert verifier.verify(f"Bearer {token}").role is Role.ADMIN


def test_scheme_is_case_insensitive(verifier: TokenVerifier, mint: Minter) -> None:
    # RFC 7235: the auth-scheme name is case-insensitive.
    assert verifier.verify(f"bearer {mint()}").role is Role.VIEWER


# --- Missing / malformed header ---------------------------------------------------


@pytest.mark.parametrize("header", [None, ""])
def test_missing_credentials(verifier: TokenVerifier, header: str | None) -> None:
    assert _reason(verifier, header) == "missing"


@pytest.mark.parametrize(
    "header",
    [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        "Bearer a b",
        "Token abc.def.ghi",
        "Bearer not-a-jwt",
        "Bearer " + "a" * 9000,  # oversize: refused before any parsing
    ],
)
def test_malformed_credentials(verifier: TokenVerifier, header: str) -> None:
    assert _reason(verifier, header) == "malformed"


# --- Signature and algorithm attacks --------------------------------------------


def test_unsigned_alg_none_token_is_rejected(verifier: TokenVerifier) -> None:
    def b64(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "role": "admin", "exp": now + 60}
    token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(claims)}."
    assert _reason(verifier, f"Bearer {token}") == "invalid"


def test_hs256_signed_with_public_key_is_rejected(
    verifier: TokenVerifier, rsa_public_pem: bytes
) -> None:
    # Classic algorithm confusion: an attacker HMAC-signs with the (public) RSA key,
    # hoping the verifier feeds that same key to HS256.
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "role": "admin", "exp": now + 60}
    payload = b64(json.dumps(claims).encode())
    signature = hmac.new(rsa_public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    token = f"{header}.{payload}.{b64(signature)}"
    assert _reason(verifier, f"Bearer {token}") == "invalid"


def test_token_signed_by_another_key_is_rejected(
    verifier: TokenVerifier, mint: Minter, other_rsa_key: rsa.RSAPrivateKey
) -> None:
    assert _reason(verifier, f"Bearer {mint(key=other_rsa_key, role='admin')}") == "invalid"


def test_tampered_payload_is_rejected(verifier: TokenVerifier, mint: Minter) -> None:
    header, _, signature = mint(role="viewer").split(".")
    now = int(time.time())
    escalated = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "role": "admin",
        "iat": now,
        "exp": now + 300,
    }
    payload = base64.urlsafe_b64encode(json.dumps(escalated).encode()).rstrip(b"=").decode()
    assert _reason(verifier, f"Bearer {header}.{payload}.{signature}") == "invalid"


# --- Claim validation -------------------------------------------------------------


def test_expired_token(verifier: TokenVerifier, mint: Minter) -> None:
    past = int(time.time()) - 3600
    assert _reason(verifier, f"Bearer {mint(iat=past - 60, exp=past)}") == "expired"


def test_not_yet_valid_token(verifier: TokenVerifier, mint: Minter) -> None:
    assert _reason(verifier, f"Bearer {mint(nbf=int(time.time()) + 3600)}") == "invalid"


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://evil.example/"},
        {"aud": "some-other-service"},
        {"exp": None},
        {"iss": None},
        {"aud": None},
        {"sub": None},
        {"sub": ""},
        {"sub": "x" * 257},
        {"sub": 123},
    ],
)
def test_bad_standard_claims(
    verifier: TokenVerifier, mint: Minter, claims: dict[str, object]
) -> None:
    assert _reason(verifier, f"Bearer {mint(**claims)}") == "invalid"


@pytest.mark.parametrize(
    "role", [None, "Admin", "ADMIN", " admin", "superadmin", "", ["admin"], 1, True]
)
def test_role_must_be_an_exact_known_value(
    verifier: TokenVerifier, mint: Minter, role: object
) -> None:
    # Unknown role -> deny. No case-folding: an issuer emitting "Admin" is misconfigured.
    assert _reason(verifier, f"Bearer {mint(role=role)}") == "invalid"


def test_small_clock_skew_is_tolerated(verifier: TokenVerifier, mint: Minter) -> None:
    now = int(time.time())
    assert verifier.verify(f"Bearer {mint(iat=now - 400, exp=now - 5)}").role is Role.VIEWER


# --- Key selection ------------------------------------------------------------------


def test_jwks_selects_key_by_kid(
    mint: Minter, rsa_key: rsa.RSAPrivateKey, other_rsa_key: rsa.RSAPrivateKey
) -> None:
    jwks = {
        "keys": [
            {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key())), "kid": "k1"},
            {
                **json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(other_rsa_key.public_key())),
                "kid": "k2",
            },
        ]
    }
    verifier = TokenVerifier.from_jwks(jwks, issuer=ISSUER, audience=AUDIENCE)
    assert verifier.verify(f"Bearer {mint(headers={'kid': 'k1'})}").subject == "user-123"
    k2 = mint(key=other_rsa_key, headers={"kid": "k2"}, role="admin")
    assert verifier.verify(f"Bearer {k2}").role is Role.ADMIN
    assert _reason(verifier, f"Bearer {mint(headers={'kid': 'unknown'})}") == "invalid"
    assert _reason(verifier, f"Bearer {mint()}") == "invalid"  # no kid with a multi-key JWKS


def test_symmetric_keys_in_jwks_are_refused() -> None:
    jwks = {"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "hmac"}]}
    with pytest.raises(TypeError, match="asymmetric"):
        TokenVerifier.from_jwks(jwks, issuer=ISSUER, audience=AUDIENCE)


def test_verifier_requires_at_least_one_key() -> None:
    with pytest.raises(ValueError, match="at least one"):
        TokenVerifier.from_pem([], issuer=ISSUER, audience=AUDIENCE)
