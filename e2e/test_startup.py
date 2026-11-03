"""Services refuse to start on bad configuration and say what to fix, without echoing values.

Each case writes a ``.env``, starts the real entrypoint with only that file as
configuration, and checks the exit status and the message on stderr.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

GOOD_CLIENT_KEY = secrets.token_urlsafe(24)
SERVICE_PREFIXES = (
    "LOG_",
    "APP_",
    "MCP_SERVER_",
    "GATEWAY_",
    "LLM_GATEWAY_",
    "LLM_ROUTER_",
    "ANTHROPIC_",
    "OPENAI_",
    "QUILR_",
)


def _start(module: str, env_file: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(SERVICE_PREFIXES)}
    env["QUILR_ENV_FILE"] = str(env_file)
    return subprocess.run(  # noqa: S603 - fixed argv to our own modules
        [sys.executable, "-m", module],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


def _env(tmp_path: Path, *lines: str) -> Path:
    path = tmp_path / "test.env"
    path.write_text("\n".join([*lines, ""]))
    return path


def _assert_refused(result: subprocess.CompletedProcess[str], *expected: str) -> None:
    assert result.returncode == 1
    assert "configuration error" in result.stderr
    for text in expected:
        assert text in result.stderr
    assert "Traceback" not in result.stderr  # the message only, not a stack trace


def test_llm_gateway_names_typos_and_bad_values_without_echoing_them(tmp_path: Path) -> None:
    short_key = "short-secret"  # below the 16-character minimum
    result = _start(
        "task4_model_router",
        _env(tmp_path, f"LLM_GATEWAY_API_KEYS='{json.dumps([short_key])}'", "LLM_GATEWAY_PROT=1"),
    )
    _assert_refused(result, "LLM_GATEWAY_PROT", "LLM_GATEWAY_API_KEYS.0")
    assert short_key not in result.stderr


@pytest.mark.parametrize("missing", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
def test_llm_gateway_requires_both_provider_keys(tmp_path: Path, missing: str) -> None:
    present = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} - {missing}
    lines = [f"LLM_GATEWAY_API_KEYS='{json.dumps([GOOD_CLIENT_KEY])}'"]
    lines += [f"{name}=mock-not-a-real-key" for name in present]
    result = _start("task4_model_router", _env(tmp_path, *lines))
    _assert_refused(result, f"{missing}: Field required")


def test_mcp_gateway_reports_an_unreadable_key_file(tmp_path: Path) -> None:
    result = _start(
        "task2_mcp_gateway",
        _env(
            tmp_path,
            "GATEWAY_DOWNSTREAM_URL=http://127.0.0.1:8000/mcp",
            "GATEWAY_JWT_ISSUER=https://idp.dev.local/",
            "GATEWAY_JWT_AUDIENCE=quilr-mcp-gateway",
            f"GATEWAY_JWT_PUBLIC_KEY_FILE={tmp_path / 'missing.pem'}",
        ),
    )
    _assert_refused(result, "token verification key")


def test_mcp_gateway_names_every_missing_required_value(tmp_path: Path) -> None:
    result = _start("task2_mcp_gateway", _env(tmp_path, "LOG_LEVEL=INFO"))
    _assert_refused(result, "GATEWAY_DOWNSTREAM_URL", "GATEWAY_JWT_ISSUER", "GATEWAY_JWT_AUDIENCE")


def test_stdio_server_refuses_bad_config_and_keeps_stdout_clean(tmp_path: Path) -> None:
    result = _start("task1_mcp_server", _env(tmp_path, "LOG_LEVL=DEBUG"))
    _assert_refused(result, "LOG_LEVL")
    assert result.stdout == ""  # stdout is reserved for JSON-RPC, even when refusing to start


def test_a_named_env_file_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    result = _start("task1_mcp_server", tmp_path / "typo.env")
    _assert_refused(result, "QUILR_ENV_FILE")
