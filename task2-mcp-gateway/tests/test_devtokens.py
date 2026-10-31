"""Unit tests for the development key/token tool."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from task2_mcp_gateway import devtokens
from task2_mcp_gateway.auth import Role, TokenVerifier


def test_keygen_writes_owner_only_private_key(tmp_path: Path) -> None:
    private, public = devtokens.keygen(tmp_path / "keys")
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert b"PRIVATE KEY" in private.read_bytes()
    assert b"PUBLIC KEY" in public.read_bytes()


def test_minted_token_verifies_with_the_public_key(tmp_path: Path) -> None:
    private, public = devtokens.keygen(tmp_path)
    token = devtokens.mint(private, role="admin", subject="root")
    verifier = TokenVerifier.from_pem(
        [public.read_bytes()], issuer=devtokens.DEFAULT_ISSUER, audience=devtokens.DEFAULT_AUDIENCE
    )
    principal = verifier.verify(f"Bearer {token}")
    assert (principal.subject, principal.role) == ("root", Role.ADMIN)


def test_cli_prints_only_the_token(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    devtokens.main(["keygen", "--dir", str(tmp_path)])
    capsys.readouterr()
    devtokens.main(["mint", "--key", str(tmp_path / "private.pem"), "--role", "viewer"])
    out = capsys.readouterr().out.strip()
    assert out.count(".") == 2  # header.payload.signature, nothing else on stdout
