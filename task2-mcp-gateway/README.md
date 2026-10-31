# Task 2: MCP security gateway (tool filtering and auth)

An HTTP reverse proxy that sits between an AI agent and an MCP server
(Streamable HTTP transport). It authenticates every request with a signed
Bearer JWT, reads the caller's role, inspects the JSON-RPC message, and
**blocks `admin_*` tool calls from non-admins at the gateway**. The
downstream server never sees a denied call.

```
agent ──HTTP──► gateway :8080 ── auth → parse → authorize ──HTTP──► MCP server :9000
                     │                                              (mock_downstream)
                     └─► 401 / -32001 / -32601 / … answered here, never forwarded
```

## Requirements → implementation

| Requirement (ASSESSMENT.md) | Where | Proven by |
|---|---|---|
| Read `Bearer <token>`, extract role (`admin` / `viewer`) | `auth.py`: signed-JWT verification, exact `role` claim | `test_auth.py` (45 tests) |
| `tools/list` forwarded transparently | `policy.py` allows it for every role; `proxy.py` streams the response back | `test_proxy.py::test_tools_list_is_forwarded_transparently`, integration |
| `tools/call` with `params.name` starting `admin_` requires `admin` | `policy.authorize` | `test_policy.py`, `test_proxy.py`, integration |
| Otherwise return `-32001: Unauthorized Tool Call` **without calling downstream** | `proxy.py` answers directly | Recording fake downstream asserts zero requests; the integration test checks the real server's execution log |

## Run it

```bash
uv sync
uv run python -m task2_mcp_gateway.devtokens keygen --dir var/keys     # stands in for an IdP
uv run python -m task2_mcp_gateway.mock_downstream --port 9000 &        # MCP server to protect

GATEWAY_DOWNSTREAM_URL=http://127.0.0.1:9000/mcp \
GATEWAY_JWT_ISSUER=https://idp.dev.local/ GATEWAY_JWT_AUDIENCE=quilr-mcp-gateway \
GATEWAY_JWT_PUBLIC_KEY_FILE=var/keys/public.pem \
uv run python -m task2_mcp_gateway                                      # gateway on :8080

uv run python -m task2_mcp_gateway.devtokens mint --role viewer --sub alice   # prints a token
```

Point any MCP client at `http://127.0.0.1:8080/mcp` with
`Authorization: Bearer <token>`. All settings are in `.env.example`.

### A real session (curl, abridged)

```text
viewer → tools/list
  ← 200 data: {"id":1,"result":{"tools":[{"name":"get_status"},{"name":"list_users"},
                                        {"name":"admin_reset_key"},{"name":"admin_delete_user"}]}}
viewer → tools/call admin_reset_key
  ← 200 {"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"Unauthorized Tool Call",
         "data":{"request_id":"67c69c53…","details":[{"field":"params.name",
         "message":"this tool requires role 'admin'","type":"insufficient_role"}]}}}
viewer → tools/call get_status        ← 200 result {"tool":"get_status","status":"executed"}
admin  → tools/call admin_reset_key   ← 200 result {"tool":"admin_reset_key","status":"executed"}
(no token) → tools/list
  ← 401  WWW-Authenticate: Bearer realm="mcp-gateway"
         {"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Authentication required",…}}

downstream log, tools actually executed:  get_status, admin_reset_key (the admin's call)
gateway audit:  tools_call deny  alice admin_reset_key | tools_call allow alice get_status |
                tools_call allow root admin_reset_key  | authenticate deny (missing)
```

**Measured overhead:** about **0.7 ms added at p50 and p95** over calling the
server directly. That's 300 sequential `tools/list` calls on loopback, after
warm-up (direct p50 0.65 ms, through the gateway 1.32 ms), well within
QuilrAI's < 50 ms enforcement budget.

## Decisions (made with the user)

| Question | Decision | Why |
|---|---|---|
| Token format | Signed JWT (RS256/ES256) verified with a **public key** or JWKS | IdP-compatible (Auth0, Okta). The gateway holds no signing secret, so compromising it can't mint admin tokens. |
| HTTP status for `-32001` | **200** with the JSON-RPC error | JSON-RPC convention; MCP clients surface it as a normal tool error. Missing or bad tokens are still **401**. |
| Methods other than `tools/list` / `tools/call` | Forward **MCP-defined methods only**; others get `-32601` | Fail closed. The list comes from the installed SDK. |

## Design, and why

**Order of checks: cheapest and most decisive first.** Token (401) → content
type (415) → body size, streamed and capped at 1 MiB (413) → strict parse
(400) → policy (200 with a JSON-RPC error) → forward. An unauthenticated
caller can't make the gateway buffer or parse a byte.

**Parse strictly, then forward exactly what was authorized.** The gateway
authorizes what *it* parsed, and downstream executes what *it* parses. Any
difference between the two parsers is a bypass, so the gateway rejects:
- **duplicate keys** (`{"name":"admin_x","name":"get_status"}`): Python keeps
  the last, other parsers keep the first;
- **`NaN`/`Infinity`**;
- **batches** (removed from MCP in 2025-06-18; a classic smuggling surface);
- **non-string or non-integer ids**, and over-deep nesting (including nesting
  deep enough to make the parser itself recurse out);
- anything that can't be re-encoded as strict JSON: lone surrogates
  (`"\ud800"`) and numbers that overflow to infinity (`1e400`).

Allowed messages are **re-serialised from the parsed object** as strict JSON
(`Message.canonical`), so downstream receives byte-for-byte what was checked.

**The `admin_` check is normalisation-robust.** It runs on the NFKC-normalised,
trimmed, case-folded name, so `ADMIN_x`, `" admin_x"` and full-width spellings
are caught even if a downstream resolves names leniently. A false positive can
only deny a viewer; a false negative would be privilege escalation.

**Routing headers must agree with the body.** MCP 2026-07-28 mirrors the
method and tool name in `Mcp-Method` / `Mcp-Name` headers. If they disagree
with the body, the gateway rejects the request (`-32600`), so a downstream
that routed on headers can't be steered to a tool the gateway never
authorized. `Mcp-Name` is decoded with the SDK's own helper (it may carry a
`=?base64?…?=` wrapper), so both sides read it identically; a malformed
wrapper never matches. (The SDK server also rejects mismatches; this is
defence in depth.)

**Headers cross only through allowlists.** Request headers forwarded:
`accept`, `content-type`, `mcp-*`, `last-event-id`. Response headers
returned: `content-type`, `cache-control`, `mcp-session-id`,
`mcp-protocol-version`, `retry-after`. So the client's `Authorization`,
cookies and `Origin` never reach downstream, and downstream's `Set-Cookie`
and `Server` never reach the client. The downstream URL comes only from
config. Redirects aren't followed, and client `X-Forwarded-*` headers aren't
trusted.

**Responses and errors.** One JSON-RPC envelope everywhere:
`{"code","message","data":{"request_id","details"?}}`, with `X-Request-ID` on
every response.

| Situation | HTTP | JSON-RPC |
|---|---|---|
| Missing / invalid / expired token | 401 + RFC 6750 `WWW-Authenticate` | `-32000` |
| Wrong content type / body too large | 415 / 413 | `-32600` |
| Unparseable / malformed message | 400 | `-32700` / `-32600` |
| Unknown method; bad `params.name` | 200 | `-32601` / `-32602` |
| Viewer calls `admin_*` | 200 | **`-32001` Unauthorized Tool Call** |
| Downstream unreachable / timed out | 502 / 504 | `-32002`, no hostnames or error text |
| Unknown path / HTTP method (incl. HEAD, OPTIONS) | 404 / 405 | `-32600` |
| Any unexpected error in the gateway | 500 | `-32603`; the traceback only in the log |

**Stack choice.** Starlette (a thin ASGI app; no framework logic on the hot
path), uvicorn, httpx (async streaming with explicit connect/read/write
timeouts) and PyJWT with `cryptography`. The gateway speaks JSON-RPC over HTTP
itself. From the MCP SDK it uses only `decode_header_value`, so it decodes
`Mcp-Name` exactly as the downstream server does. The rest of the SDK is used
for the mock downstream server and the interoperability test.

## Security considerations

- **Fail closed:** unknown role, unknown method, unparseable token or body, or
  an unreachable downstream all mean nothing is forwarded.
- **Token checks:** an algorithm allowlist with **asymmetric keys only**, so
  `alg: none` and "HS256 signed with the public key" are impossible (both
  tested). `exp`/`iss`/`aud`/`sub` are required. `role` must be exactly
  `admin` or `viewer` (`"Admin"`, `["admin"]` and `"superadmin"` are denied).
- **Audit:** every tool-call allow/deny and every authentication failure emits
  a structured audit event (`quilr_common`) with the principal and request id.
  Token contents and tool arguments are never logged.

## Tests

```bash
uv run pytest task2-mcp-gateway -q
```

| Suite | Tests | What it proves |
|---|---|---|
| `test_auth.py` | 45 | Token parsing, `alg:none`, algorithm confusion, wrong key, tampering, expiry, `nbf`, issuer/audience, exact role values, JWKS `kid` selection, hostile `kid`/`crit` headers |
| `test_policy.py` | 67 | The brief's rules; bypass attempts (case, whitespace, full-width, header mismatch including base64-encoded headers, duplicate keys, batches); method allowlist; pathological nesting, surrogates, `1e400` |
| `test_proxy.py` | 35 | The HTTP layer against a **recording fake downstream**: denied requests produce zero downstream calls; header stripping; re-serialised body; SSE streaming; 401/413/415; sanitised 502/504; enveloped 404/405/500 |
| `test_devtokens.py` | 3 | Key file permissions (0600); minted tokens verify |
| `test_integration.py` | 5 | **Real processes on real sockets**: gateway in front of the SDK-based MCP server; denials never executed (checked in the downstream log); the official SDK client works through the gateway |

## Known limitations

- **Sessions aren't bound to a principal.** `Mcp-Session-Id` belongs to the
  downstream server, and authorization happens per request, so a session
  shared between tokens grants no extra privilege. The gateway doesn't stop
  two different tokens from using one session id, though.
- **Keys are loaded from files** (PEM or JWKS) at start-up. Fetching a JWKS URL
  with caching and key rotation would be the production step.
- **`tools/list` isn't filtered by role.** The brief asks for transparent
  forwarding, so viewers can *see* admin tools but not call them.
- **Responses and the GET SSE stream aren't inspected.** Scanning tool outputs
  for injected instructions is a separate guardrail.
- No rate limiting or multiple downstreams. One gateway protects one MCP server.
