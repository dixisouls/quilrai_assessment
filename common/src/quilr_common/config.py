"""How every service loads its settings: environment variables plus a ``.env`` file.

Sources, highest priority first:

1. **Real environment variables.** This is how Docker, CI and orchestrators
   configure a process, so they always win.
2. **The ``.env`` file**, read by the service itself at startup (no ``source``
   needed). It is ``./.env`` in the working directory by default.
   ``QUILR_ENV_FILE`` names another file, and an empty ``QUILR_ENV_FILE``
   turns file loading off. The test suite turns it off so a developer's
   ``.env`` can never change test results.
3. **Defaults declared on each settings class.** Secrets and other values with
   no safe default have none, so a service refuses to start without them.

Only entrypoints load the file, through :func:`load_settings`. Settings
classes don't name it in their ``model_config``, so code and tests that build
a settings object directly never read a developer's ``.env``.

One ``.env`` holds the variables for every service, so each settings class
reads only its own prefix (``dotenv_filtering="match_prefix"``). An unknown
variable *with* that prefix is still rejected at startup by
``extra="forbid"``. That catches typos such as ``LLM_GATEWAY_PROT``, which
would otherwise be silently ignored.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from quilr_common.log.settings import ServiceInfo

ENV_FILE_VAR: Final = "QUILR_ENV_FILE"
DEFAULT_ENV_FILE: Final = Path(".env")


class ConfigError(SystemExit):
    """Invalid or missing configuration at startup.

    A ``SystemExit`` subclass, so an entrypoint that doesn't catch it exits with
    status 1 and prints only the message, not a traceback. The message names
    the variables and the rules they broke, never their values, because a
    rejected value may be a secret.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


def env_file() -> Path | None:
    """The ``.env`` file to read, or ``None`` when file loading is turned off."""
    raw = os.environ.get(ENV_FILE_VAR)
    if raw is None:
        return DEFAULT_ENV_FILE
    return Path(raw) if raw.strip() else None


def load_settings[S: BaseSettings](cls: type[S]) -> S:
    """Build ``cls`` from the environment and the ``.env`` file (see the module docs).

    A missing default ``./.env`` is fine: the environment alone may configure
    the process. A file named explicitly in ``QUILR_ENV_FILE`` must exist, so a
    typo in the path can't silently start a service on defaults.
    """
    path = env_file()
    if path is not None and os.environ.get(ENV_FILE_VAR) and not path.is_file():
        raise ConfigError(f"configuration error: {ENV_FILE_VAR} names a file that does not exist")
    try:
        return cls(_env_file=path)
    except ValidationError as exc:
        raise ConfigError(_describe(cls, exc)) from None  # `from None`: the cause holds values


def _describe(cls: type[BaseSettings], exc: ValidationError) -> str:
    prefix = str(cls.model_config.get("env_prefix") or "")
    problems = []
    for err in exc.errors(include_input=False, include_url=False, include_context=False):
        field = ".".join(str(part) for part in err["loc"])
        problems.append(f"{prefix}{field}".upper() + f": {err['msg']}")
    return "configuration error: " + "; ".join(problems)


class AppSettings(BaseSettings):
    """Process-wide identity, from ``APP_*`` variables."""

    model_config = SettingsConfigDict(
        env_prefix="APP_", extra="forbid", frozen=True, dotenv_filtering="match_prefix"
    )

    env: str = Field(default="dev", min_length=1, max_length=32)


def service_info(name: str, version: str) -> ServiceInfo:
    """The identity stamped on every log line, with ``APP_ENV`` from the configuration."""
    return ServiceInfo(name=name, version=version, env=load_settings(AppSettings).env)
