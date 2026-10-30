"""Request-scoped logging context, propagated with :mod:`contextvars`.

``contextvars`` (not thread-locals) is the correct primitive under asyncio. Each
task gets a copy of its parent's context, so concurrent requests on one event
loop never see each other's request IDs.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any, Final

_EMPTY: Final[MappingProxyType[str, Any]] = MappingProxyType({})
_context: ContextVar[MappingProxyType[str, Any]] = ContextVar("quilr_log_context", default=_EMPTY)

# Client-supplied correlation IDs (e.g. an X-Request-ID header) are attacker
# controlled. Only a conservative charset is accepted, so they can't inject log
# lines, break parsers, or smuggle bidi/control characters.
_SAFE_REQUEST_ID: Final = re.compile(r"[A-Za-z0-9._-]{1,128}")


def get_context() -> dict[str, Any]:
    """Return a copy of the fields bound to the current context."""
    return dict(_context.get())


@contextmanager
def bind_context(**fields: Any) -> Iterator[None]:
    """Bind ``fields`` for the duration of the ``with`` block (nesting merges)."""
    token = _context.set(MappingProxyType({**_context.get(), **fields}))
    try:
        yield
    finally:
        _context.reset(token)


def new_request_id() -> str:
    """Generate a new, unguessable request ID (UUID4, 32 lowercase hex chars)."""
    return uuid.uuid4().hex


def sanitize_request_id(value: str | None) -> str:
    """Accept a client-supplied request ID only if it is safe, else mint a new one."""
    if value is not None and _SAFE_REQUEST_ID.fullmatch(value):
        return value
    return new_request_id()
