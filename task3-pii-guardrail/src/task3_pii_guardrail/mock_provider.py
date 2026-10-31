"""Mock Anthropic Messages API (SSE wire format) for tests and offline demos.

Replies "You said: <last user message>" in 3-character text deltas, so a PII
value in the prompt is guaranteed to be split across stream chunks. Markers in
the user message script failures:

* ``[[status:429]]`` / ``[[status:529]]`` → error response with that status
* ``[[slow]]`` → pause 1 s after the second delta (by then "You " is complete)
* ``[[midstream-error]]`` → an ``overloaded_error`` event after a few deltas

Run: ``python -m task3_pii_guardrail.mock_provider --port 9090`` and point the
gateway at it with ``LLM_GATEWAY_ANTHROPIC_BASE_URL=http://127.0.0.1:9090``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

_MARKER = re.compile(r"\[\[[a-z0-9:-]+\]\]")
_ERROR_TYPES = {429: "rate_limit_error", 529: "overloaded_error", 500: "api_error"}


def _event(name: str, data: dict[str, Any]) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()


async def _messages(request: Request) -> Response:
    body = await request.json()
    user = next((m["content"] for m in reversed(body["messages"]) if m["role"] == "user"), "")
    if (status := re.search(r"\[\[status:(\d{3})\]\]", user)) is not None:
        code = int(status.group(1))
        return JSONResponse(
            {
                "type": "error",
                "error": {"type": _ERROR_TYPES.get(code, "api_error"), "message": "mock"},
            },
            status_code=code,
            headers={"retry-after": "3"} if code == 429 else None,  # noqa: PLR2004
        )
    text = "You said: " + _MARKER.sub("", user).strip()

    async def events() -> AsyncIterator[bytes]:
        yield _event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "model": body["model"],
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                },
            },
        )
        yield _event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
        yield _event("ping", {"type": "ping"})
        for n, i in enumerate(range(0, len(text), 3)):
            yield _event(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": text[i : i + 3]},
                },
            )
            if n == 1 and "[[slow]]" in user:
                await asyncio.sleep(1.0)
            if n == 4 and "[[midstream-error]]" in user:  # noqa: PLR2004
                yield _event(
                    "error",
                    {
                        "type": "error",
                        "error": {"type": "overloaded_error", "message": "Overloaded"},
                    },
                )
                return
        yield _event("content_block_stop", {"type": "content_block_stop", "index": 0})
        yield _event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": len(text) // 4},
            },
        )
        yield _event("message_stop", {"type": "message_stop"})

    return StreamingResponse(events(), media_type="text/event-stream")


def create_mock_app() -> Starlette:
    return Starlette(routes=[Route("/v1/messages", _messages, methods=["POST"])])


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Anthropic Messages API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9090)
    args = parser.parse_args()
    uvicorn.run(create_mock_app(), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
