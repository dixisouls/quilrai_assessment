"""Bearer-token verification: signed JWT → :class:`Principal` (subject + role).

The gateway only ever holds **public** keys, from PEM files or a JWKS document
as published by an IdP such as Auth0 or Okta. Whoever compromises the gateway
still can't mint tokens.

Verification, in order (any failure → :class:`AuthError`, i.e. HTTP 401):

1. ``Authorization: Bearer <token>``. The scheme is case-insensitive (RFC 7235),
   the token is ≤ 8 KiB and in RFC 6750 ``b64token`` syntax.
2. The header ``alg`` must be in the allowlist (RS256 / ES256 by default).
   ``none`` and every HMAC algorithm are impossible because only asymmetric keys
   are loaded, which also defeats the "HS256 signed with the public key"
   algorithm-confusion attack.
3. Signature against a key of the right type. With a multi-key JWKS the token
   must name its key with ``kid``.
4. Claims: ``exp``, ``iss``, ``aud`` and ``sub`` required; ``exp``/``nbf``
   checked with a small leeway for clock skew.
5. ``role`` must be *exactly* ``"admin"`` or ``"viewer"``. No case-folding, no
   lists, no defaults. An unknown role is denied (fail closed).

``AuthError.reason`` is what the client is told (RFC 6750 style). The
specific failed check goes to the log via ``detail`` only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

MAX_TOKEN_CHARS: Final = 8192
DEFAULT_ALGORITHMS: Final = ("RS256", "ES256")
_BEARER: Final = re.compile(r"(?i:bearer) ([A-Za-z0-9\-._~+/]+=*)")
_REQUIRED_CLAIMS: Final = ["exp", "iss", "aud", "sub"]
_MAX_SUBJECT_CHARS: Final = 256

type PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey
AuthFailure = Literal["missing", "malformed", "expired", "invalid"]


class Role(StrEnum):
    ADMIN = "admin"
    VIEWER = "viewer"


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    role: Role


class AuthError(Exception):
    """Authentication failed. ``reason`` is client-facing; ``detail`` is for logs only."""

    def __init__(self, reason: AuthFailure, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: AuthFailure = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class _Key:
    key: PublicKey
    kid: str | None


def _key_matches_alg(key: PublicKey, alg: str) -> bool:
    if alg.startswith(("RS", "PS")):
        return isinstance(key, rsa.RSAPublicKey)
    if alg.startswith("ES"):
        return isinstance(key, ec.EllipticCurvePublicKey)
    return False


class TokenVerifier:
    def __init__(
        self,
        keys: Iterable[_Key],
        *,
        issuer: str,
        audience: str,
        algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
        leeway_s: int = 30,
    ) -> None:
        self._keys = list(keys)
        if not self._keys:
            raise ValueError("token verifier needs at least one public key")
        bad = [a for a in algorithms if not a.startswith(("RS", "PS", "ES"))]
        if bad:
            raise ValueError(f"only asymmetric algorithms may be allowed, got {bad}")
        self._issuer = issuer
        self._audience = audience
        self._algorithms = list(algorithms)
        self._leeway = leeway_s

    @classmethod
    def from_pem(cls, pems: Iterable[bytes], **kwargs: Any) -> TokenVerifier:
        keys = []
        for pem in pems:
            key = load_pem_public_key(pem)
            if not isinstance(key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
                raise TypeError("only RSA and EC public keys are supported")
            keys.append(_Key(key, None))
        return cls(keys, **kwargs)

    @classmethod
    def from_jwks(cls, jwks: Mapping[str, Any], **kwargs: Any) -> TokenVerifier:
        keys = []
        for jwk in jwt.PyJWKSet.from_dict(dict(jwks)).keys:
            if not isinstance(jwk.key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
                raise TypeError(f"JWKS key {jwk.key_id!r} is not an asymmetric public key")
            keys.append(_Key(jwk.key, jwk.key_id))
        return cls(keys, **kwargs)

    # --- verification -----------------------------------------------------------

    def verify(self, authorization: str | None) -> Principal:
        token = self._extract(authorization)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:  # DecodeError, bad kid/crit types, ...
            raise AuthError("malformed", f"unusable JWT header: {exc}") from None
        alg = header.get("alg")
        if alg not in self._algorithms:
            raise AuthError("invalid", f"algorithm {alg!r} not allowed")
        claims = self._decode(token, alg, header.get("kid"))
        return self._principal(claims)

    @staticmethod
    def _extract(authorization: str | None) -> str:
        if not authorization:
            raise AuthError("missing", "no Authorization header")
        if len(authorization) > MAX_TOKEN_CHARS:
            raise AuthError("malformed", "Authorization header too long")
        match = _BEARER.fullmatch(authorization)
        if match is None:
            raise AuthError("malformed", "not a Bearer credential")
        return match.group(1)

    def _candidates(self, alg: str, kid: object) -> list[_Key]:
        keys = [k for k in self._keys if _key_matches_alg(k.key, alg)]
        if any(k.kid is not None for k in self._keys) and len(self._keys) > 1:
            # JWKS with several keys: the token must say which one.
            keys = [k for k in keys if kid is not None and k.kid == kid]
        return keys

    def _decode(self, token: str, alg: str, kid: object) -> dict[str, Any]:
        candidates = self._candidates(alg, kid)
        if not candidates:
            raise AuthError("invalid", f"no key for alg={alg} kid={kid!r}")
        for candidate in candidates:
            try:
                claims: dict[str, Any] = jwt.decode(
                    token,
                    candidate.key,
                    algorithms=[alg],
                    audience=self._audience,
                    issuer=self._issuer,
                    leeway=self._leeway,
                    options={"require": _REQUIRED_CLAIMS},
                )
            except jwt.InvalidSignatureError:
                continue  # try the next key of the same type
            except jwt.ExpiredSignatureError:
                raise AuthError("expired", "token expired") from None
            except jwt.DecodeError as exc:
                raise AuthError("malformed", f"undecodable JWT: {type(exc).__name__}") from None
            except jwt.InvalidTokenError as exc:
                raise AuthError("invalid", f"claim check failed: {type(exc).__name__}") from None
            return claims
        raise AuthError("invalid", "signature does not verify with any configured key")

    @staticmethod
    def _principal(claims: Mapping[str, Any]) -> Principal:
        sub = claims.get("sub")
        if not isinstance(sub, str) or not 0 < len(sub) <= _MAX_SUBJECT_CHARS:
            raise AuthError("invalid", "sub must be a non-empty string of at most 256 chars")
        role = claims.get("role")
        # isinstance(str) excludes lists, numbers and booleans; membership is exact.
        if not isinstance(role, str) or role not in Role._value2member_map_:
            raise AuthError("invalid", "role claim missing or not an allowed value")
        return Principal(subject=sub, role=Role(role))
