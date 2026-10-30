# Task 1: MCP server with strict validation over stdio

An MCP server built on the official Python SDK (`mcp` 2.3) that exposes two
tools:

| Tool | Inputs | Effect |
|---|---|---|
| `get_customer_record` | `customer_id`: `CUST-XXXXX` | Read-only lookup |
| `trigger_refund` | `customer_id`, `amount` (positive number), `reason` (≥ 10 chars) | Moves money; not idempotent |

It speaks JSON-RPC over **stdio**. **stdout carries only JSON-RPC messages**,
and every log line goes to stderr as structured JSON.

## Run it

```bash
uv sync
uv run python -m task1_mcp_server        # or: uv run task1-mcp-server
```

Register it with any MCP client (Claude Desktop, Claude Code, the SDK client):

```json
{ "mcpServers": { "quilr-customer-tools": {
    "command": "uv", "args": ["run", "--directory", "/path/to/repo", "task1-mcp-server"] } } }
```

Demo customers: `CUST-00042` (active, $250), `CUST-00101` (active, $1000),
`CUST-10001` (active, $75), `CUST-00666` (suspended), `CUST-00999` (closed).

### A real session

Output from piping raw JSON-RPC into the server (`initialize` response omitted):

```text
→ tools/call get_customer_record {"customer_id":"CUST-00042"}
← {"id":1,"result":{"isError":false,"structuredContent":{"customer_id":"CUST-00042","name":"Ada Lovelace",
   "email":"ada@example.com","tier":"gold","status":"active","refundable_balance":"250.00"}, "content":[…]}}

→ tools/call trigger_refund {"customer_id":"CUST-00042","amount":19.99,"reason":"Duplicate charge on order 1182"}
← {"id":2,"result":{"isError":false,"structuredContent":{"refund_id":"RF-EF97212B42194D34","amount":"19.99",
   "currency":"USD","status":"accepted","remaining_refundable_balance":"230.01", …}}}

→ tools/call trigger_refund {"customer_id":"cust-42","amount":"19.99","reason":"oops"}
← {"id":3,"error":{"code":-32602,"message":"Invalid params","data":{"errors":[
   {"field":"customer_id","message":"String should match pattern '^CUST-[0-9]{5}$'","type":"string_pattern_mismatch"},
   {"field":"amount","message":"Value error, amount must be a JSON number","type":"value_error"},
   {"field":"reason","message":"String should have at least 10 characters","type":"string_too_short"}]}}}

→ tools/call trigger_refund {"customer_id":"CUST-00666","amount":5,"reason":"Goodwill credit for delay"}
← {"id":4,"result":{"isError":true,"content":[{"type":"text","text":"Customer account is not active."}]}}

→ {oops
← {"id":null,"error":{"code":-32700,"message":"Parse error"}}
```

stderr for the same session (one JSON object per line, abridged):

```text
{"level":"INFO","logger":"task1_mcp_server.service","msg":"tool succeeded","tool":"get_customer_record","latency_ms":0.01,…}
{"level":"INFO","logger":"quilr.audit","msg":"audit tool.trigger_refund allow","log_type":"audit",
 "audit":{"decision":"allow","resource":"CUST-00042","metadata":{"amount":"19.99","reason_chars":30,"refund_id":"RF-…"}},…}
```

## Design, and why this approach

### 1. How each failure is answered

The brief asks for invalid input to be rejected "with standard MCP JSON-RPC
error codes". MCP has two error channels, and each has a deliberate use here:

| Failure | Response | Why |
|---|---|---|
| Arguments fail the schema; unknown tool | JSON-RPC **`-32602` Invalid params** with `data.errors[] = {field, message, type}` | Required by the brief. The request is malformed, so it never reaches business logic. Every violation is reported at once. |
| Valid input, but a business rule says no (unknown customer, suspended account, refund over balance) | **`result.isError: true`** with a short, fixed message | The *call* was well-formed and its outcome is a refusal. That is MCP's "tool execution error", which the model can read and act on. |
| Unexpected exception | JSON-RPC **`-32603` Internal error** with only `data.correlation_id` | No internals reach the client. The traceback is in the stderr log under the same id. |
| Line isn't JSON | **`-32700` Parse error**, `id: null` | JSON-RPC 2.0 requires it; the SDK would otherwise drop the line silently. |
| JSON but not a valid request (batch, wrong version, missing method) | **`-32600` Invalid Request**, `id: null` | Same. MCP doesn't support batches. |
| Unknown method | **`-32601`** (from the SDK) | Spec |

**Input values are never echoed** in `-32602` data. Only the field name, the
rule and the error type are, because the rejected value might be PII or a
prompt-injection payload aimed at the calling model. Likewise, an unknown tool
name isn't reflected back; the response lists the available tools instead.

### 2. Why the low-level `Server`, not `MCPServer` (formerly FastMCP)

I read the SDK source and ran a spike before choosing:

- `MCPServer` reports argument-validation failures as `isError` *results*,
  which matches newer MCP guidance for model self-correction but not the brief.
  The low-level `Server` lets `CustomerToolService` validate first and raise a
  real `-32602`.
- The spike also showed that an exception escaping a low-level handler reaches
  the client **verbatim with `code: 0`** (not even a valid JSON-RPC code). The
  service therefore catches everything unexpected and returns a sanitised
  `-32603`.

### 3. One source of truth for the schema

The Pydantic models in `models.py` both **validate** `tools/call` arguments and
**generate** the JSON Schemas advertised by `tools/list` (`additionalProperties:
false`, `pattern`, `exclusiveMinimum`, `minLength`, …). What the client is told
and what the server enforces can't drift apart. A test asserts the published
constraints.

### 4. Validation rules, including the edge cases

| Field | Rule | Edge cases handled |
|---|---|---|
| `customer_id` | Full match `^CUST-[0-9]{5}$` | `[0-9]` instead of `\d`, because Python's `\d` matches Arabic-Indic and full-width digits. No trimming or case-folding (`cust-12345`, `" CUST-12345"` and a trailing `\n` are rejected). Non-strings are rejected. |
| `amount` | JSON number, finite, `> 0`, `≤ 10,000`, ≤ 2 decimal places | Numeric strings (`"25"`) and booleans (`true`) are rejected, not coerced. `NaN`/`Infinity` (accepted by Python's `json`) are rejected. The value is converted to `Decimal` via `repr`, so `0.1` becomes exactly `0.10`; money never touches float arithmetic, and it is serialised back as a decimal *string* (`"19.99"`). |
| `reason` | Trimmed, then 10–500 chars, no control or format characters | Whitespace-only and `"  short   "` are rejected. Newlines, NUL and bidi overrides are rejected, since they enable log or record injection downstream. |
| (any) | `additionalProperties: false` | `{"customer_id": …, "include_ssn": true}` → `-32602`, field `include_ssn` |

The brief leaves some details open, so I chose the strict reading and
documented it here. `XXXXX` is taken as 5 digits. The `10,000` cap and the
2-decimal rule are business guards that a refund tool should have.

### 5. stdout isolation: three layers, each tested

1. **Logging** is configured with `stdout_reserved=True` before anything else
   runs, so the logging library refuses any stdout sink. `print` is banned by
   ruff (`T20`).
2. **The SDK** points fd 1 at stderr while serving and writes the wire through
   a private duplicate, so raw `os.write(1, …)` can't reach the wire.
3. **`transport.py`** covers what the SDK misses. `print()` and
   `sys.stdout.write` are buffered on a pipe and would be flushed onto the real
   stdout *after* the SDK restores fd 1. So once fd 1 is claimed, `sys.stdout`
   is redirected to stderr for the session and flushed at both ends. (I first
   believed layer 2 was enough; the integration test proved otherwise. See
   `MISTAKES.md` T1.)

`test_internal_errors_do_not_leak_and_stdout_survives_stray_writes` runs a
server whose store calls `print()`, `sys.stdout.write()` and `os.write(1)` and
then crashes. Every stdout line must still parse as JSON-RPC, and the stray
text must show up in stderr.

### 6. Security and audit

- Refund decisions (allow and deny) emit **audit events** through the shared
  `quilr_common` audit logger. They record the amount and the *length* of the
  reason, never its text.
- Tool annotations tell clients that `trigger_refund` is destructive and not
  idempotent, and that `get_customer_record` is read-only.
- No authentication in this server. A stdio server runs as a child of the
  client process, inside the user's trust boundary; per-user authorization
  belongs in the gateway (Task 2).

## Code layout

```
src/task1_mcp_server/
  models.py     strict input schemas + output models (validation + JSON Schema source)
  store.py      CustomerStore protocol, in-memory implementation, business-rule errors
  service.py    tool catalogue, dispatch, error mapping, audit, logging
  server.py     wires the service into the SDK's low-level Server
  transport.py  stdio serving: stdout redirect + -32700/-32600 replies
  __main__.py   entry point: logging first, then serve
```

## Tests

```bash
uv run pytest task1-mcp-server -q
```

99 tests:

| Suite | What it proves |
|---|---|
| `test_models.py` (65) | Every validation rule and edge case above, the strictness of the published schemas, and that all errors come back together |
| `test_store.py` (6) | Business rules; refused refunds leave balances untouched |
| `test_service.py` (18) | Error-class mapping, no input echo, no leak of internals, correlation id in logs, tool annotations |
| `test_stdio_integration.py` (10) | A real subprocess over raw pipes: a full session, every malformed-line class, stdout purity under stray writes and crashes, and interoperability with the **official SDK client** |

## Known limitations

- **In-memory store.** Balances reset on restart. Refunds have no idempotency
  key, so a client retrying after a lost response could refund twice; a real
  backend would need one.
- **Shutdown at EOF.** Per the MCP stdio lifecycle the client closes stdin
  after receiving its responses. A request still in flight when stdin closes
  may be cancelled.
- **Non-integer ids.** The SDK reads a request with a non-integer numeric id
  (e.g. `1.5`) as a notification and doesn't answer it. MCP only allows
  string or integer ids, and fixing this would mean replacing the SDK's stdin
  reader, which relies on its private file-descriptor API.
- **Line length.** The SDK's stdin reader doesn't bound line length. That's
  acceptable for a local child process; a network-facing deployment would sit
  behind a gateway with body-size limits (Task 2).
