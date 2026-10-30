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
← {"id":3,"error":{"code":-32602,"message":"Invalid params","data":{"request_id":"69f95555870d4f28a4bfa140f2ffde02","details":[
   {"field":"customer_id","message":"String should match pattern '^CUST-[0-9]{5}$'","type":"string_pattern_mismatch"},
   {"field":"amount","message":"Value error, amount must be a JSON number","type":"value_error"},
   {"field":"reason","message":"String should have at least 10 characters","type":"string_too_short"}]}}}

→ tools/call trigger_refund {"customer_id":"CUST-00666","amount":5,"reason":"Goodwill credit for delay"}
← {"id":4,"result":{"isError":true,"content":[{"type":"text","text":"Customer account is not active."}]}}

→ {oops
← {"id":null,"error":{"code":-32700,"message":"Parse error","data":{"request_id":"ac519cacd66744e38e05cf84aa135f09"}}}
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

Every error uses one envelope: `data.request_id` (also written to the stderr
log, so a client report can be matched to the server's record) and, for
`-32602`, `data.details[] = {field, message, type}`.

| Failure | Response | Why |
|---|---|---|
| Arguments fail the schema; unknown tool; `params.name` not a string; `params.arguments` not an object | JSON-RPC **`-32602` Invalid params** with `data.details` | Required by the brief. The request is malformed, so it never reaches business logic. Every violation is reported at once. |
| Valid input, but a business rule says no (unknown customer, suspended account, refund over balance) | **`result.isError: true`** with a short, fixed message | The *call* was well-formed and its outcome is a refusal. That is MCP's "tool execution error", which the model can read and act on. |
| Unexpected exception | JSON-RPC **`-32603` Internal error** with only `data.request_id` | No internals reach the client. The traceback is in the stderr log under the same id. |
| Line isn't JSON | **`-32700` Parse error**, `id: null` | JSON-RPC 2.0 requires it; the SDK would otherwise drop the line silently. |
| JSON but not a valid request (batch, wrong version, `params` not an object, missing method) | **`-32600` Invalid Request**, echoing `id` when it can be read, else `null` | Same; the spec requires echoing a readable id. MCP doesn't support batches. |
| Unknown method | **`-32601`** (from the SDK) | Spec |

**Caller input is never echoed** in error data. Messages come from our own
validators. Field names are reported only when they are plain identifiers; an
attacker-chosen key such as `"IGNORE PREVIOUS INSTRUCTIONS…"` comes back as
`"(unexpected field)"`. An unknown tool name isn't reflected either; the
detail lists the available tools instead.

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
false`, `pattern`, `exclusiveMinimum`, `maxLength`, …). Tests pin the published
constraints and check that the advertised `reason` pattern and the validator
agree. The advertised schema is allowed to be slightly *looser* than the
server but never *stricter*. For example, there is deliberately no
`"multipleOf": 0.01` on `amount`: the Python `jsonschema` library rejects
11,426 of 100,000 valid cent amounts (such as `0.07`) with it, because of float
division. A regression test runs `jsonschema` over the amounts to keep it that
way.

### 4. Validation rules, including the edge cases

| Field | Rule | Edge cases handled |
|---|---|---|
| `customer_id` | Full match `^CUST-[0-9]{5}$` | `[0-9]` instead of `\d`, because Python's `\d` matches Arabic-Indic and full-width digits. No trimming or case-folding (`cust-12345`, `" CUST-12345"` and a trailing `\n` are rejected). Non-strings are rejected. |
| `amount` | JSON number, finite, `> 0`, `≤ 10,000`, ≤ 2 decimal places | Numeric strings (`"25"`) and booleans (`true`) are rejected, not coerced. `NaN`/`Infinity` (accepted by Python's `json`) are rejected. The value is converted to `Decimal` via `repr`, so `0.1` becomes exactly `0.10`; all arithmetic is decimal, and amounts are serialised back as decimal *strings* (`"19.99"`). See the limitation on float parsing below. |
| `reason` | Trimmed, then 10–500 chars, no code point in Unicode categories Cc/Cf/Zl/Zp/Co/Cn/Cs | Whitespace-only and `"  short   "` are rejected. Newlines, NUL, U+2028/U+2029 line separators, bidi overrides, zero-width and private-use characters are all rejected, since they enable log or record injection or deceptive rendering downstream. |
| (any) | `additionalProperties: false` | `{"customer_id": …, "include_ssn": true}` → `-32602`, field `include_ssn` |

The brief leaves some details open, so I chose the strict reading and
documented it here. `XXXXX` is taken as 5 digits. The `10,000` cap and the
2-decimal rule are business guards that a refund tool should have.

### 5. stdout isolation: three layers, each tested

1. **Logging** is configured first, to stderr, with `stdout_reserved=True`,
   so the logging library refuses any stdout sink. `print` is banned by ruff
   (`T20`).
2. **`reserve_stdout()`** runs next, before the server is built. It moves the
   protocol to a private duplicate of fd 1, then points fd 1 *and*
   `sys.stdout` at stderr **for the rest of the process**. From then on,
   `print`, `sys.stdout`, `sys.__stdout__`, `os.write(1)`, C extensions,
   child processes and `atexit` handlers all write to stderr.
3. **The SDK's `stdio_server`** writes JSON-RPC only to that private stream.

My first version relied on the SDK's own fd-1 diversion. It only covers the
session window, and Python's stdout buffer was flushed onto the real stdout
afterwards (`MISTAKES.md` T1). The review then found pre-session and `atexit`
writes leaking too (Review #2 finding 5). Two integration tests now pin this
down. One store calls `print()`, `sys.stdout.write()` and `os.write(1)` and
then crashes. The other writes before the session starts and from an `atexit`
handler, with and without `PYTHONUNBUFFERED`. In both, every stdout line must
parse as JSON-RPC.

### 6. Every request gets its answer, even if stdin closes at once

A client may write its requests and close stdin immediately
(`cat requests.jsonl | server`). The SDK then cancels in-flight handlers and
its stdout writer, so a refund could commit while its receipt was dropped.
The review reproduced this in 20 of 20 runs. The transport now tracks
accepted request ids and the lines actually written to stdout, and keeps the
session alive until every accepted request has been answered *and* written
(bounded at 10 s). A stress run of 30 sessions under saturated CPU delivers
every reply in all 30; an intermediate version with a hand-off race managed
only 10 of 30 (`MISTAKES.md` R2-1).

### 7. Security and audit

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
  errors.py     JSON-RPC error envelope (request_id, details), safe field naming
  service.py    tool catalogue, dispatch, error mapping, audit, logging
  server.py     wires the service into the SDK's low-level Server
  transport.py  stdout reservation, drain-before-exit, -32700/-32600/-32602 replies
  __main__.py   entry point: logging first, then serve
```

## Tests

```bash
uv run pytest task1-mcp-server -q
```

129 tests; total branch coverage is 98.9%, with the spawned server processes
measured too:

| Suite | What it proves |
|---|---|
| `test_models.py` (82) | Every validation rule and edge case above, Python values and raw JSON text, schema strictness, pattern/validator agreement, `jsonschema` never rejecting a valid amount |
| `test_store.py` (6) | Business rules; refused refunds leave balances untouched |
| `test_service.py` (23) | Error-class mapping, the error envelope, no echo of values or hostile field names, no leak of internals, request id in the logs, tool annotations |
| `test_stdio_integration.py` (18) | A real subprocess over raw pipes: a full session, every malformed-message class (with id echo), stdout purity during and outside the session, no lost replies when stdin closes at once, and interoperability with the **official SDK client** |

## Known limitations

- **Amounts arrive as binary floats.** The SDK parses the JSON line before any
  validator runs, so digits beyond float precision (~17 significant digits)
  are already gone: `19.989999999999999` arrives as `19.99` and is accepted.
  The ≤ 2-decimal rule therefore applies to the parsed value. The brief
  specifies a float, so the contract is kept; a production payments API should
  take integer cents or a decimal string.
- **In-memory store.** Balances reset on restart. Refunds have no idempotency
  key; a real backend should require one.
- **Requests the SDK never answers.** A request whose `id` is not a string or
  an integer (`1.5`, `true`, `null`, `{}`) is read by the SDK as a
  notification and gets no reply. MCP only allows string or integer ids;
  answering these would mean replacing the SDK's stdin reader.
- **Before `initialize`.** A `tools/call` sent before the handshake gets the
  SDK's `-32602 "Invalid request parameters"`; that answer comes from the SDK
  session layer, not from this server's code.
- **Import-time writes.** Anything written to stdout while Python imports the
  modules, before `run()` reserves stdout, isn't covered. Nothing in this
  codebase does that.
- **Line length.** The SDK's stdin reader doesn't bound line length. That's
  acceptable for a local child process; a network-facing deployment sits
  behind a gateway with body-size limits (Task 2).
