"""Repo-wide test setup: a developer's ``.env`` never changes test results.

Services load ``.env`` themselves at startup (``quilr_common.config``). The
tests configure every server they start explicitly, so here file loading is
turned off for the whole run. Spawned servers inherit this environment
variable, so it applies to them too.

Live tests (``RUN_LIVE_TESTS=1``) are the one exception: they need the real
provider keys, so only ``ANTHROPIC_API_KEY`` and ``OPENAI_API_KEY`` are read
from ``.env`` (unless already set in the environment). Nothing else in the
file is used, so a live run can't pick up other local settings either.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import dotenv_values

os.environ["QUILR_ENV_FILE"] = ""

_LIVE_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")

if os.environ.get("RUN_LIVE_TESTS") == "1":
    _values = dotenv_values(Path(__file__).parent / ".env")
    for _name in _LIVE_KEYS:
        _value = _values.get(_name)
        if _value and _name not in os.environ:
            os.environ[_name] = _value
