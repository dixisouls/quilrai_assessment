"""Gateway configuration (``GATEWAY_*`` environment variables)."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from task2_mcp_gateway.auth import DEFAULT_ALGORITHMS, TokenVerifier


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", extra="forbid", frozen=True)

    # Where allowed traffic goes. Configuration only: never derived from a request.
    downstream_url: HttpUrl

    # Token verification. Exactly one key source is needed to run the server.
    jwt_issuer: str = Field(min_length=1)
    jwt_audience: str = Field(min_length=1)
    jwt_public_key_file: Path | None = None
    jwks_file: Path | None = None
    jwt_algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    jwt_leeway_s: int = Field(default=30, ge=0, le=300)

    # Limits and timeouts.
    max_body_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    connect_timeout_s: float = Field(default=5.0, gt=0, le=60)
    request_timeout_s: float = Field(default=60.0, gt=0, le=600)
    stream_timeout_s: float = Field(default=300.0, gt=0, le=3600)

    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)

    @model_validator(mode="after")
    def _one_key_source_at_most(self) -> GatewaySettings:
        if self.jwt_public_key_file is not None and self.jwks_file is not None:
            raise ValueError("set GATEWAY_JWT_PUBLIC_KEY_FILE or GATEWAY_JWKS_FILE, not both")
        return self

    def build_verifier(self) -> TokenVerifier:
        common = {
            "issuer": self.jwt_issuer,
            "audience": self.jwt_audience,
            "algorithms": self.jwt_algorithms,
            "leeway_s": self.jwt_leeway_s,
        }
        if self.jwks_file is not None:
            return TokenVerifier.from_jwks(json.loads(self.jwks_file.read_text()), **common)
        if self.jwt_public_key_file is not None:
            return TokenVerifier.from_pem([self.jwt_public_key_file.read_bytes()], **common)
        raise ValueError(
            "no token key configured: set GATEWAY_JWT_PUBLIC_KEY_FILE or GATEWAY_JWKS_FILE"
        )
