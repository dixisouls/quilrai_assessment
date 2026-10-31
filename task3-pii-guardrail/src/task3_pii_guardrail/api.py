"""OpenAI-compatible endpoint that streams provider output through the PII redactor.

``POST /v1/chat/completions`` → authenticate → validate → call the provider →
stream ``chat.completion.chunk`` events whose text has passed through
:class:`StreamRedactor`. ``GET /healthz`` for orchestrators.

Latency and memory:

* The response is committed (HTTP 200 + SSE headers) only after the provider's
  **first event** arrives, so a provider failure before any output (429,
  outage) is still a proper HTTP error. Every delta after that is redacted and
  forwarded as soon as it's safe. The only text ever buffered is the
  redactor's bounded hold-back.
* If the provider fails mid-stream, the client gets an SSE ``error`` event and
  ``[DONE]``. Held text is *discarded*, not flushed, because it may be the
  start of a value only the lost remainder would have identified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
import uuid
from collections.abc import AsyncGenerator, AsyncIterator, Mapping
from typing import Any, Final

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from quilr_common.log import (
    AuditEvent,
    Decision,
    bind_context,
    emit_audit,
    get_logger,
    sanitize_request_id,
)
from task3_pii_guardrail.config import GatewaySettings
from task3_pii_guardrail.models import ChatRequest
from task3_pii_guardrail.providers import BlockEnd, Finish, Provider, ProviderError, ProviderEvent
from task3_pii_guardrail.redactor import StreamRedactor, redact_counted

log = get_logger(__name__)

_PROVIDER_STATUS: Final = {
    "rate_limited": 429,
    "unavailable": 502,
    "timeout": 504,
    "bad_request": 502,
}
_PROVIDER_MESSAGE: Final = {
    "rate_limited": "The model provider is rate limiting requests. Retry later.",
    "unavailable": "The model provider is unavailable.",
    "timeout": "The model provider timed out.",
    "bad_request": "The model provider rejected the request.",
}


def _error_body(
    message: str, kind: str, request_id: str, param: str | None = None
) -> dict[str, Any]:
    return {
        "message": message,
        "type": kind,
        "code": None,
        "param": param,
        "request_id": request_id,
    }


def _retry_after_header(value: float | None) -> dict[str, str] | None:
    # Defence in depth: providers already sanitise, but never let a bad value 500.
    if value is None or not math.isfinite(value) or not 0 <= value <= 3600:  # noqa: PLR2004
        return None
    return {"retry-after": str(int(value))}


def _error(
    status: int,
    message: str,
    kind: str,
    request_id: str,
    *,
    param: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body = {
        "error": {
            "message": message,
            "type": kind,
            "code": None,
            "param": param,
            "request_id": request_id,
        }
    }
    return JSONResponse(
        body, status_code=status, headers={"x-request-id": request_id, **(headers or {})}
    )


def _provider_error(exc: ProviderError, request_id: str) -> JSONResponse:
    log.warning("provider error", extra={"kind": exc.kind, "detail": exc.detail})
    headers = _retry_after_header(exc.retry_after)
    kind = "rate_limit_error" if exc.kind == "rate_limited" else "provider_error"
    return _error(
        _PROVIDER_STATUS[exc.kind], _PROVIDER_MESSAGE[exc.kind], kind, request_id, headers=headers
    )


def _sse(obj: object) -> bytes:
    payload = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))
    return f"data: {payload}\n\n".encode()


class _Gateway:
    def __init__(self, settings: GatewaySettings, provider: Provider, model_name: str) -> None:
        self._settings = settings
        self._provider = provider
        self._model_name = model_name
        self._keys = [k.get_secret_value().encode() for k in settings.api_keys]

    def _authenticate(self, header: str | None) -> str | None:
        """Return a non-reversible principal id for a valid key, else None."""
        if not header or not header.lower().startswith("bearer "):
            return None
        presented = header[7:].encode()  # exact bytes: no stripping, so blank tokens can't match
        valid = False
        for key in self._keys:  # check every key: timing doesn't reveal which matched
            valid |= hmac.compare_digest(presented, key)
        return f"key-{hashlib.sha256(presented).hexdigest()[:12]}" if valid else None

    async def chat_completions(self, request: Request) -> Response:
        request_id = sanitize_request_id(request.headers.get("x-request-id"))
        with bind_context(request_id=request_id):
            principal = self._authenticate(request.headers.get("authorization"))
            if principal is None:
                return _error(
                    401, "Invalid or missing API key.", "authentication_error", request_id
                )
            with bind_context(principal=principal):
                return await self._handle(request, request_id, principal)

    async def _handle(self, request: Request, request_id: str, principal: str) -> Response:
        chat = await self._parse(request, request_id)
        if isinstance(chat, Response):
            return chat
        events = self._provider.stream(chat)
        try:
            first: ProviderEvent = await anext(events)
        except StopAsyncIteration:
            first = Finish("stop")
        except ProviderError as exc:
            await events.aclose()
            return _provider_error(exc, request_id)
        except Exception:
            await events.aclose()
            log.exception("provider failed before first event")
            return _error(500, "Internal error.", "internal_error", request_id)

        if chat.stream:
            return StreamingResponse(
                self._stream(events, first, request_id, principal),
                media_type="text/event-stream",
                headers={
                    "x-request-id": request_id,
                    "cache-control": "no-cache",
                    "x-accel-buffering": "no",
                },
            )
        return await self._complete(events, first, request_id)

    async def _parse(self, request: Request, request_id: str) -> ChatRequest | Response:
        body = await self._read_body(request)
        if body is None:
            return _error(413, "Request body too large.", "invalid_request_error", request_id)
        try:
            return ChatRequest.model_validate(json.loads(body, parse_constant=_reject_constant))
        except ValidationError as exc:
            error = exc.errors(include_url=False, include_input=False)[0]
            param = ".".join(str(p) for p in error["loc"]) or None
            return _error(400, error["msg"], "invalid_request_error", request_id, param=param)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return _error(
                400, "Request body is not valid JSON.", "invalid_request_error", request_id
            )

    async def _read_body(self, request: Request) -> bytes | None:
        limit = self._settings.max_body_bytes
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            return None
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    def _chunk(
        self, completion_id: str, created: int, delta: dict[str, Any], finish: str | None
    ) -> bytes:
        return _sse(
            {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": self._model_name,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }
        )

    async def _stream(
        self,
        events: AsyncGenerator[ProviderEvent, None],
        first: ProviderEvent,
        request_id: str,
        principal: str,
    ) -> AsyncIterator[bytes]:
        # Starlette iterates this generator after the handler (and its bind_context)
        # has returned, so the log context is re-bound here for audit and errors.
        with bind_context(request_id=request_id, principal=principal):
            async for chunk in self._stream_body(events, first, request_id):
                yield chunk

    async def _stream_body(
        self, events: AsyncGenerator[ProviderEvent, None], first: ProviderEvent, request_id: str
    ) -> AsyncIterator[bytes]:
        completion_id, created = f"chatcmpl-{uuid.uuid4().hex}", int(time.time())
        redactor = StreamRedactor()
        redactions = 0
        finish: Finish | None = None
        try:
            yield self._chunk(completion_id, created, {"role": "assistant", "content": ""}, None)
            event: ProviderEvent | None = first
            while event is not None:
                if isinstance(event, Finish):
                    finish = event
                    break
                if isinstance(event, BlockEnd):
                    # Each content block is redacted independently (see BlockEnd).
                    if tail := redactor.flush():
                        yield self._chunk(completion_id, created, {"content": tail}, None)
                    redactions += redactor.redactions
                    redactor = StreamRedactor()
                elif safe := redactor.feed(event):
                    yield self._chunk(completion_id, created, {"content": safe}, None)
                event = await anext(events, None)
            if tail := redactor.flush():
                yield self._chunk(completion_id, created, {"content": tail}, None)
            yield self._chunk(completion_id, created, {}, (finish or Finish("stop")).reason)
        except ProviderError as exc:
            redactor.discard()
            log.warning(
                "provider failed mid-stream", extra={"kind": exc.kind, "detail": exc.detail}
            )
            yield _sse(
                {"error": _error_body(_PROVIDER_MESSAGE[exc.kind], "provider_error", request_id)}
            )
        except Exception:
            redactor.discard()
            log.exception("gateway failed mid-stream")
            yield _sse({"error": _error_body("Internal error.", "internal_error", request_id)})
        finally:
            await events.aclose()  # also runs when the client disconnects
            self._audit(redactions + redactor.redactions)
        yield _sse("[DONE]")

    async def _complete(
        self, events: AsyncGenerator[ProviderEvent, None], first: ProviderEvent, request_id: str
    ) -> Response:
        blocks: list[list[str]] = [[]]
        finish = Finish("stop")
        try:
            event: ProviderEvent | None = first
            while event is not None:
                if isinstance(event, Finish):
                    finish = event
                    break
                if isinstance(event, BlockEnd):
                    blocks.append([])
                else:
                    blocks[-1].append(event)
                event = await anext(events, None)
        except ProviderError as exc:
            return _provider_error(exc, request_id)
        except Exception:
            log.exception("provider failed while collecting a non-streaming response")
            return _error(500, "Internal error.", "internal_error", request_id)
        finally:
            await events.aclose()
        # Same rule as streaming: each content block is redacted independently.
        redacted = [redact_counted("".join(parts)) for parts in blocks]
        text = "".join(t for t, _ in redacted)
        self._audit(sum(n for _, n in redacted))
        return JSONResponse(
            {
                "id": f"chatcmpl-{uuid.uuid4().hex}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": self._model_name,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": text},
                        "finish_reason": finish.reason,
                    }
                ],
            },
            headers={"x-request-id": request_id},
        )

    @staticmethod
    def _audit(redactions: int) -> None:
        if redactions:
            emit_audit(
                AuditEvent(
                    action="llm.response_redaction",
                    decision=Decision.REDACT,
                    reason=f"{redactions} sensitive value(s) redacted from the model response",
                    metadata={"count": redactions},
                )
            )


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON constant {name}")


async def _healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def create_app(
    settings: GatewaySettings, provider: Provider, *, model_name: str | None = None
) -> Starlette:
    gateway = _Gateway(settings, provider, model_name or settings.model)
    app = Starlette(
        routes=[
            Route("/v1/chat/completions", gateway.chat_completions, methods=["POST"]),
            Route("/healthz", _healthz, methods=["GET"]),
        ]
    )
    app.router.redirect_slashes = False
    return app
