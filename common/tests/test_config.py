"""Settings loading: environment variables plus the ``.env`` file."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from quilr_common.config import (
    ENV_FILE_VAR,
    AppSettings,
    ConfigError,
    env_file,
    load_settings,
    service_info,
)
from quilr_common.log import LoggingSettings

SECRET = "s3cr3t-value-that-must-never-be-echoed"


class DemoSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DEMO_", extra="forbid", frozen=True, dotenv_filtering="match_prefix"
    )

    token: SecretStr = Field(min_length=16)
    port: int = Field(default=8000, ge=1, le=65535)
    keys: list[SecretStr] = Field(default_factory=list)  # JSON in the environment, like API keys


def _write_env(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "test.env"
    path.write_text(text)
    return path


@pytest.fixture(autouse=True)
def _no_demo_vars_in_the_real_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DEMO_TOKEN", "DEMO_PORT", "DEMO_PROT", "DEMO_KEYS", "LOG_LEVEL", "APP_ENV"):
        monkeypatch.delenv(name, raising=False)


def _point_at(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv(ENV_FILE_VAR, str(path))


# --- Which file -------------------------------------------------------------------------


def test_default_file_is_dot_env_in_the_working_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    assert env_file() == Path(".env")


@pytest.mark.parametrize("value", ["", "  "])
def test_blank_variable_turns_file_loading_off(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(ENV_FILE_VAR, value)
    assert env_file() is None


def test_the_test_suite_never_reads_a_developer_env_file() -> None:
    # Set by the repo-level conftest.py; servers spawned by tests inherit it.
    assert env_file() is None


def test_missing_default_file_is_fine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here
    monkeypatch.setenv("DEMO_TOKEN", SECRET)
    assert load_settings(DemoSettings).port == 8000


def test_explicitly_named_file_must_exist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _point_at(monkeypatch, tmp_path / "typo.env")
    with pytest.raises(ConfigError, match="names a file that does not exist"):
        load_settings(DemoSettings)


# --- What is read -----------------------------------------------------------------------


def test_values_come_from_the_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _point_at(monkeypatch, _write_env(tmp_path, f"DEMO_TOKEN={SECRET}\nDEMO_PORT=9123\n"))
    settings = load_settings(DemoSettings)
    assert settings.port == 9123
    assert settings.token.get_secret_value() == SECRET


def test_real_environment_variables_win_over_the_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _point_at(monkeypatch, _write_env(tmp_path, f"DEMO_TOKEN={SECRET}\nDEMO_PORT=9123\n"))
    monkeypatch.setenv("DEMO_PORT", "9999")
    assert load_settings(DemoSettings).port == 9999


def test_the_default_dot_env_is_read_without_sourcing_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".env").write_text(f"DEMO_TOKEN={SECRET}\nDEMO_PORT=9124\n")
    monkeypatch.delenv(ENV_FILE_VAR, raising=False)
    monkeypatch.chdir(tmp_path)
    assert load_settings(DemoSettings).port == 9124


def test_one_shared_file_serves_every_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared = (
        f"DEMO_TOKEN={SECRET}\n"
        "ANTHROPIC_API_KEY=not-for-this-service\n"
        "GATEWAY_PORT=8080\n"
        "LOG_LEVEL=WARNING\n"
        "APP_ENV=staging\n"
    )
    _point_at(monkeypatch, _write_env(tmp_path, shared))
    assert load_settings(DemoSettings).port == 8000  # other prefixes are ignored
    assert load_settings(LoggingSettings).level == "WARNING"
    assert load_settings(AppSettings).env == "staging"
    assert service_info("svc", "1.0").env == "staging"


# --- Errors say what to fix, never the value ---------------------------------------------


def test_typo_in_own_prefix_is_rejected_by_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _point_at(monkeypatch, _write_env(tmp_path, f"DEMO_TOKEN={SECRET}\nDEMO_PROT=9123\n"))
    with pytest.raises(ConfigError) as info:
        load_settings(DemoSettings)
    assert "DEMO_PROT" in str(info.value)
    assert "Extra inputs are not permitted" in str(info.value)


def test_missing_required_value_is_named(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _point_at(monkeypatch, _write_env(tmp_path, "DEMO_PORT=9123\n"))
    with pytest.raises(ConfigError, match=r"DEMO_TOKEN: Field required"):
        load_settings(DemoSettings)


def test_rejected_values_are_never_echoed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    short = "short-secret"  # 12 characters; the rule is at least 16
    _point_at(monkeypatch, _write_env(tmp_path, f"DEMO_TOKEN={short}\nDEMO_PORT={SECRET}\n"))
    with pytest.raises(ConfigError) as info:
        load_settings(DemoSettings)
    text = str(info.value)
    assert "DEMO_TOKEN" in text
    assert "DEMO_PORT" in text
    assert short not in text
    assert SECRET not in text
    assert info.value.__cause__ is None  # the pydantic error (which holds values) is dropped
    assert info.value.__suppress_context__


def test_config_error_exits_with_status_1_and_only_the_message() -> None:
    err = ConfigError("configuration error: X: Field required")
    assert isinstance(err, SystemExit)
    assert str(err) == "configuration error: X: Field required"
    assert err.code == "configuration error: X: Field required"  # printed, exit status 1


@pytest.mark.parametrize("value", ["", SECRET, "[unclosed", "'single-quoted inside'"])
def test_list_values_that_are_not_json_are_named_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    # The most likely mistake: a bare key instead of '["key"]', or an empty value.
    _point_at(monkeypatch, _write_env(tmp_path, f"DEMO_TOKEN={SECRET}\nDEMO_KEYS={value}\n"))
    with pytest.raises(ConfigError) as info:
        load_settings(DemoSettings)
    text = str(info.value)
    assert text.startswith("configuration error: DEMO_KEYS: missing or not valid JSON")
    assert SECRET not in text
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_list_values_in_json_are_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env = f"DEMO_TOKEN={SECRET}\nDEMO_KEYS='[\"{SECRET}\"]'\n"
    _point_at(monkeypatch, _write_env(tmp_path, env))
    [key] = load_settings(DemoSettings).keys
    assert key.get_secret_value() == SECRET


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_env_file_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _write_env(tmp_path, f"DEMO_TOKEN={SECRET}\n")
    path.chmod(0)
    try:
        _point_at(monkeypatch, path)
        with pytest.raises(ConfigError, match="cannot read the env file") as info:
            load_settings(DemoSettings)
        assert SECRET not in str(info.value)
    finally:
        path.chmod(0o600)
