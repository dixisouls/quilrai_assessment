"""OpenAI-compatible request schema (``POST /v1/chat/completions``), validated strictly."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=200_000)


class ChatRequest(BaseModel):
    """The subset of the OpenAI Chat Completions request this gateway supports.

    Unknown fields (``temperature``, ``tools``, …) are rejected with a 400 that
    names the field, instead of being silently dropped. ``model`` is required
    for client compatibility; the gateway routes to its configured provider
    model (see README).
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    model: str = Field(min_length=1, max_length=128)
    messages: list[ChatMessage] = Field(min_length=1, max_length=256)
    stream: bool = False
    max_tokens: int | None = Field(default=None, ge=1, le=64_000)

    @field_validator("messages")
    @classmethod
    def _conversation_shape(cls, messages: list[ChatMessage]) -> list[ChatMessage]:
        turns = [m for m in messages if m.role != "system"]
        if not turns or turns[0].role != "user":
            raise ValueError("the first non-system message must have role 'user'")
        return messages
