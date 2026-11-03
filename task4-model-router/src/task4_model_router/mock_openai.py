"""Mock OpenAI Chat Completions API (streaming wire format) for tests and offline demos.

Replies "Backup says: <last user message>" in 3-character deltas, then a usage
chunk (as with ``stream_options.include_usage``) and ``[DONE]``. Markers in the
user message script failures:

* ``[[openai:429]]`` / ``[[openai:500]]`` → error response with that status
* ``[[openai-hang:N]]`` → wait N seconds before answering

Run: ``python -m task4_model_router.mock_openai --port 9092``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from collections.abc import AsyncIterator
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

_MARKER = re.compile(r"\[\[[a-z0-9:-]+\]\]")
REQUESTS: list[dict[str, Any]] = []  # in-process inspection by tests


def _chunk(cid: str, model: str, delta: dict[str, Any], finish: str | None) -> bytes:
    body = {
        "id": cid,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    return f"data: {json.dumps(body)}\n\n".encode()


async def _completions(request: Request) -> Response:
    body = await request.json()
    REQUESTS.append(body)
    user = next((m["content"] for m in reversed(body["messages"]) if m["role"] == "user"), "")
    if (hang := re.search(r"\[\[openai-hang:(\d+)\]\]", user)) is not None:
        await asyncio.sleep(int(hang.group(1)))
    if (status := re.search(r"\[\[openai:(\d{3})\]\]", user)) is not None:
        code = int(status.group(1))
        return JSONResponse(
            {
                "error": {
                    "message": "mock",
                    "type": "rate_limit_exceeded" if code == 429 else "server_error",  # noqa: PLR2004
                    "param": None,
                    "code": None,
                }
            },
            status_code=code,
            headers={"retry-after": "4"} if code == 429 else None,  # noqa: PLR2004
        )
    text = "Backup says: " + _MARKER.sub("", user).strip()
    model, cid = body["model"], "chatcmpl-mock"

    async def events() -> AsyncIterator[bytes]:
        yield _chunk(cid, model, {"role": "assistant", "content": ""}, None)
        for i in range(0, len(text), 3):
            yield _chunk(cid, model, {"content": text[i : i + 3]}, None)
        yield _chunk(cid, model, {}, "stop")
        usage = {"prompt_tokens": 11, "completion_tokens": len(text) // 4, "total_tokens": 0}
        final = {
            "id": cid,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [],
            "usage": usage,
        }
        yield f"data: {json.dumps(final)}\n\n".encode()
        yield b"data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


def create_mock_app() -> Starlette:
    return Starlette(routes=[Route("/v1/chat/completions", _completions, methods=["POST"])])


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock OpenAI Chat Completions API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9092)
    args = parser.parse_args()
    uvicorn.run(create_mock_app(), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
