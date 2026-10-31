"""Development token tooling: generate a key pair and mint signed JWTs.

In production an IdP (Auth0, Okta, …) issues tokens and the gateway only
gets its public key or JWKS. This tool stands in for that IdP locally::

    python -m task2_mcp_gateway.devtokens keygen --dir var/keys
    python -m task2_mcp_gateway.devtokens mint --key var/keys/private.pem --role viewer --sub alice

The private key is written with mode 0600 into a directory that is
git-ignored (``var/``). It never needs to leave the developer machine.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DEFAULT_ISSUER = "https://idp.dev.local/"
DEFAULT_AUDIENCE = "quilr-mcp-gateway"


def keygen(directory: Path) -> tuple[Path, Path]:
    """Create an ES256 (P-256) key pair; return (private, public) paths."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    private = directory / "private.pem"
    public = directory / "public.pem"
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


def mint(
    private_key: Path,
    *,
    role: str,
    subject: str,
    ttl_s: int = 3600,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
) -> str:
    key = load_pem_private_key(private_key.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("expected an EC private key created by `keygen`")
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + ttl_s,
    }
    return jwt.encode(claims, key, algorithm="ES256")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dev keys and tokens for the MCP gateway.")
    sub = parser.add_subparsers(dest="command", required=True)
    kg = sub.add_parser("keygen", help="create an ES256 key pair")
    kg.add_argument("--dir", type=Path, default=Path("var/keys"))
    mt = sub.add_parser("mint", help="mint a signed token")
    mt.add_argument("--key", type=Path, default=Path("var/keys/private.pem"))
    mt.add_argument("--role", required=True, help="admin or viewer (anything else is denied)")
    mt.add_argument("--sub", default="dev-user")
    mt.add_argument("--ttl", type=int, default=3600)
    mt.add_argument("--iss", default=DEFAULT_ISSUER)
    mt.add_argument("--aud", default=DEFAULT_AUDIENCE)
    args = parser.parse_args(argv)

    if args.command == "keygen":
        private, public = keygen(args.dir)
        sys.stdout.write(f"private key: {private}\npublic key:  {public}\n")
    else:
        token = mint(
            args.key,
            role=args.role,
            subject=args.sub,
            ttl_s=args.ttl,
            issuer=args.iss,
            audience=args.aud,
        )
        sys.stdout.write(token + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
