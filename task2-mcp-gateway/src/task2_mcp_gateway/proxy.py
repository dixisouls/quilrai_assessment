"""The gateway: authenticate → parse → authorize → forward, as an ASGI app.

``POST /mcp`` carries JSON-RPC messages (MCP Streamable HTTP). ``GET /mcp``
(server-to-client SSE stream) and ``DELETE /mcp`` (end session) carry no
JSON-RPC body; they're authenticated and forwarded. ``GET /healthz`` is for
orchestrators.

Order of checks, cheapest and most decisive first, so an unauthenticated
caller can't make the gateway buffer or parse anything:

1. Bearer token → 401 with an RFC 6750 ``WWW-Authenticate`` challenge.
2. ``Content-Type`` (415), then body size, streamed and capped (413).
3. Strict JSON-RPC parse (400 with ``-32700`` / ``-32600``).
4. Authorization policy (200 with ``-32601`` / ``-32602`` / ``-32001``).
5. Forward the *re-serialised* message to the configured downstream URL and
   stream its response back (JSON or SSE). Failures become sanitised 502/504
   responses carrying ``-32002``.
6. A downstream *error* response (HTTP 4xx/5xx) is never relayed verbatim; see
   :func:`_sanitise_downstream_error`.

Headers cross the gateway only from an explicit allowlist in each direction.
The client's ``Authorization`` never reaches downstream, and downstream's
internal headers (``Set-Cookie``, ``Server``, …) never reach the client.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import AsyncIterator, Mapping
from typing import Any, Final

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from quilr_common.log import (
    AuditEvent,
    Decision,
    bind_context,
    emit_audit,
    get_logger,
    new_request_id,
    sanitize_request_id,
)
from task2_mcp_gateway.auth import AuthError, Principal, TokenVerifier
from task2_mcp_gateway.config import GatewaySettings
from task2_mcp_gateway.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JsonRpcError,
    JsonRpcId,
    Message,
    parse_message,
)
from task2_mcp_gateway.policy import UNAUTHORIZED_TOOL_CALL, authorize

log = get_logger(__name__)

_ALLOWED_HTTP_METHODS: Final = frozenset({"POST", "GET", "DELETE"})
_REFUSED_HTTP_METHODS: Final = ("HEAD", "OPTIONS", "PUT", "PATCH")

AUTHENTICATION_REQUIRED: Final = -32000
DOWNSTREAM_UNAVAILABLE: Final = -32002

# Request headers forwarded to downstream: what MCP Streamable HTTP needs, nothing else.
_FORWARD_REQUEST: Final = frozenset(
    {
        "accept",
        "content-type",
        "last-event-id",
        "mcp-session-id",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
    }
)
_FORWARD_REQUEST_PREFIX: Final = "mcp-param-"
# Response headers returned to the client.
_RETURN_RESPONSE: Final = frozenset(
    {"content-type", "cache-control", "mcp-session-id", "mcp-protocol-version", "retry-after"}
)
# Downstream error bodies are read only up to this size; anything larger isn't relayed.
_MAX_DOWNSTREAM_ERROR_BYTES: Final = 64 * 1024
# Messages the gateway sends for relayed downstream errors. Downstream's own text
# is never forwarded: the MCP SDK puts raw validation output (input values,
# library names) in it, and a misconfigured server may return anything.
_STANDARD_MESSAGES: Final = {
    PARSE_ERROR: "Parse error",
    INVALID_REQUEST: "Invalid Request",
    METHOD_NOT_FOUND: "Method not found",
    INVALID_PARAMS: "Invalid params",
}
_AUTH_DESCRIPTIONS: Final = {
    "expired": "token expired",
    "malformed": "malformed token",
    "invalid": "token rejected",
}


def _error(
    status: int,
    code: int,
    message: str,
    request_id: str,
    *,
    rpc_id: JsonRpcId | None = None,
    details: list[dict[str, str]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    data: dict[str, Any] = {"request_id": request_id}
    if details:
        data["details"] = details
    body = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": code, "message": message, "data": data},
    }
    return JSONResponse(
        body, status_code=status, headers={"x-request-id": request_id, **(headers or {})}
    )


class _Gateway:
    def __init__(
        self, settings: GatewaySettings, verifier: TokenVerifier, client: httpx.AsyncClient
    ) -> None:
        self._settings = settings
        self._verifier = verifier
        self._client = client
        self._downstream = str(settings.downstream_url)

    async def handle(self, request: Request) -> Response:
        request_id = sanitize_request_id(request.headers.get("x-request-id"))
        started = time.perf_counter()
        with bind_context(request_id=request_id):
            if request.method not in _ALLOWED_HTTP_METHODS:
                # Starlette implicitly adds HEAD to GET routes; refuse it like any other.
                response: Response = _error(
                    405,
                    INVALID_REQUEST,
                    "Method not allowed",
                    request_id,
                    headers={"allow": ", ".join(sorted(_ALLOWED_HTTP_METHODS))},
                )
            else:
                try:
                    response = await self._handle(request, request_id)
                except Exception:
                    # Never a bare 500: the client gets the envelope, the log gets the trace.
                    log.exception("unhandled error in gateway")
                    response = _error(500, INTERNAL_ERROR, "Internal error", request_id)
            log.info(
                "request handled",
                extra={
                    "http_method": request.method,
                    "status": response.status_code,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            return response

    async def _handle(self, request: Request, request_id: str) -> Response:
        try:
            principal = self._verifier.verify(request.headers.get("authorization"))
        except AuthError as exc:
            return self._unauthenticated(exc, request_id)
        with bind_context(principal=principal.subject, role=principal.role.value):
            if request.method != "POST":
                return await self._forward(request, None, None, request_id)
            return await self._handle_post(request, principal, request_id)

    async def _handle_post(
        self, request: Request, principal: Principal, request_id: str
    ) -> Response:
        content_type = request.headers.get("content-type", "")
        if content_type.split(";")[0].strip().lower() != "application/json":
            return _error(415, INVALID_REQUEST, "Content-Type must be application/json", request_id)
        body = await self._read_body(request)
        if body is None:
            return _error(413, INVALID_REQUEST, "Request body too large", request_id)
        try:
            msg = parse_message(body)
        except JsonRpcError as exc:
            return _error(400, exc.code, exc.message, request_id, rpc_id=exc.id)
        try:
            authorize(principal, msg, {k.lower(): v for k, v in request.headers.items()})
        except JsonRpcError as exc:
            self._audit_decision(principal, msg, exc)
            return _error(
                200, exc.code, exc.message, request_id, rpc_id=exc.id, details=exc.details
            )
        self._audit_decision(principal, msg, None)
        return await self._forward(request, msg, msg.canonical, request_id)

    # --- steps --------------------------------------------------------------------

    def _unauthenticated(self, exc: AuthError, request_id: str) -> JSONResponse:
        log.info("authentication failed", extra={"reason": exc.reason, "detail": exc.detail})
        emit_audit(
            AuditEvent(action="gateway.authenticate", decision=Decision.DENY, reason=exc.reason)
        )
        challenge = 'Bearer realm="mcp-gateway"'
        if exc.reason != "missing":  # RFC 6750 3.1: no error code when no credentials were sent
            challenge += (
                f', error="invalid_token", error_description="{_AUTH_DESCRIPTIONS[exc.reason]}"'
            )
        return _error(
            401,
            AUTHENTICATION_REQUIRED,
            "Authentication required",
            request_id,
            headers={"www-authenticate": challenge},
        )

    async def _read_body(self, request: Request) -> bytes | None:
        limit = self._settings.max_body_bytes
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            return None
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _audit_decision(principal: Principal, msg: Message, denial: JsonRpcError | None) -> None:
        if msg.method != "tools/call" or (
            denial is not None and denial.code != UNAUTHORIZED_TOOL_CALL
        ):
            return  # audit tool-call allow/deny decisions; malformed calls are just logged
        tool = (msg.params or {}).get("name")
        emit_audit(
            AuditEvent(
                action="gateway.tools_call",
                decision=Decision.DENY if denial else Decision.ALLOW,
                reason=f"role {principal.role.value}"
                + (" may not call admin tools" if denial else " permitted"),
                resource=tool[:256] if isinstance(tool, str) else None,
            )
        )

    async def _forward(
        self, request: Request, msg: Message | None, content: bytes | None, request_id: str
    ) -> Response:
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() in _FORWARD_REQUEST or k.lower().startswith(_FORWARD_REQUEST_PREFIX)
        }
        headers["x-request-id"] = request_id
        read = (
            self._settings.request_timeout_s
            if request.method == "POST"
            else self._settings.stream_timeout_s
        )
        timeout = httpx.Timeout(
            connect=self._settings.connect_timeout_s, read=read, write=read, pool=read
        )
        upstream = self._client.build_request(
            request.method, self._downstream, headers=headers, content=content, timeout=timeout
        )
        rpc_id = msg.id if msg is not None else None
        try:
            response = await self._client.send(upstream, stream=True)
        except httpx.TimeoutException as exc:
            log.warning("downstream timeout", extra={"error": type(exc).__name__})
            return _error(
                504, DOWNSTREAM_UNAVAILABLE, "Downstream unavailable", request_id, rpc_id=rpc_id
            )
        except httpx.HTTPError as exc:
            log.warning("downstream unreachable", extra={"error": type(exc).__name__})
            return _error(
                502, DOWNSTREAM_UNAVAILABLE, "Downstream unavailable", request_id, rpc_id=rpc_id
            )

        if response.is_error:  # 4xx or 5xx
            return await _sanitise_downstream_error(response, rpc_id, request_id)
        out = {k: v for k, v in response.headers.items() if k.lower() in _RETURN_RESPONSE}
        out["x-request-id"] = request_id
        return StreamingResponse(
            response.aiter_bytes(),  # decoded, so no content-encoding is forwarded
            status_code=response.status_code,
            headers=out,
            background=BackgroundTask(response.aclose),
        )


async def _read_capped(response: httpx.Response, limit: int) -> bytes | None:
    """The response body, or None if it is larger than ``limit`` bytes."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _jsonrpc_error_code(body: bytes | None) -> int | None:
    """The ``error.code`` of a well-formed JSON-RPC 2.0 error response, else None."""
    if body is None:
        return None
    try:
        obj = json.loads(body)
    except ValueError:  # includes UnicodeDecodeError and JSONDecodeError
        return None
    if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
        return None
    error = obj.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if type(code) is int else None  # bool is an int subclass; exclude it


async def _sanitise_downstream_error(
    response: httpx.Response, rpc_id: JsonRpcId | None, request_id: str
) -> Response:
    """Turn a downstream HTTP error into the gateway's own envelope.

    * **4xx with a JSON-RPC error body** (the MCP SDK's transport errors, such
      as an unknown session or a bad ``Accept`` header): the status and the
      JSON-RPC code are kept, because MCP clients act on them. For example, a
      404 tells a client to start a new session. The message is the gateway's
      standard text for that code, never downstream's.
    * **Anything else** (5xx, a non-JSON body, an HTML error page from a
      misconfigured server, or a body over 64 KiB): ``502`` with ``-32002``.
      The cause is downstream, not the client, and its text may expose
      internals such as stack traces, hostnames or library names.

    Downstream's status and body size go to the log (never the body itself), so
    support can find the cause by ``request_id``.
    """
    status = response.status_code
    try:
        body = await _read_capped(response, _MAX_DOWNSTREAM_ERROR_BYTES)
    except httpx.HTTPError:
        body = None
    finally:
        await response.aclose()
    code = None if response.is_server_error else _jsonrpc_error_code(body)
    log.warning(
        "downstream returned an error",
        extra={
            "status": status,
            "body_bytes": None if body is None else len(body),
            "relayed_code": code,
        },
    )
    if code is None:
        return _error(502, DOWNSTREAM_UNAVAILABLE, "Downstream error", request_id, rpc_id=rpc_id)
    headers = {
        k: v
        for k, v in response.headers.items()
        if k.lower() in _RETURN_RESPONSE and k.lower() != "content-type"
    }
    message = _STANDARD_MESSAGES.get(code, "Request rejected by the downstream server")
    return _error(status, code, message, request_id, rpc_id=rpc_id, headers=headers)


async def _healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def _http_error(_request: Request, exc: Exception) -> Response:
    """Unknown path (404) or method (405) from the router: same envelope as everything else."""
    assert isinstance(exc, HTTPException)  # noqa: S101 - registered for HTTPException only
    request_id = new_request_id()
    message = "Not found" if exc.status_code == 404 else "Method not allowed"  # noqa: PLR2004
    return _error(exc.status_code, INVALID_REQUEST, message, request_id, headers=exc.headers)


def create_app(
    settings: GatewaySettings,
    verifier: TokenVerifier,
    client: httpx.AsyncClient,
    *,
    close_client_on_shutdown: bool = False,
) -> Starlette:
    gateway = _Gateway(settings, verifier, client)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if close_client_on_shutdown:
                await client.aclose()

    app = Starlette(
        routes=[
            # HEAD/OPTIONS/PUT/... are routed in too, so the handler can refuse them
            # with the gateway's own envelope instead of Starlette's plain text.
            Route("/mcp", gateway.handle, methods=[*_ALLOWED_HTTP_METHODS, *_REFUSED_HTTP_METHODS]),
            Route("/healthz", _healthz, methods=["GET"]),
        ],
        exception_handlers={HTTPException: _http_error},
        lifespan=lifespan,
    )
    app.router.redirect_slashes = False  # /mcp/ is a 404, not a redirect to /mcp
    return app
