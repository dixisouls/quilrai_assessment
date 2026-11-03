# Task 4: rate limiting and model fallback router

The resilience layer of the LLM gateway. It plugs into Task 3, so one process
gives you the whole pipeline:

```
client ─► auth ─► token rate limiter ─► failover router ──► Anthropic (primary, claude-opus-5-5)
          (T3)    (SQLite, per key)     429 / 3000 ms ──► OpenAI (backup, gpt-6.1-sol)
       ◄──────────── streaming PII redaction (T3) ◄─────────────────────────┘
```

## Requirements → implementation

| Requirement (ASSESSMENT.md) | Where | Proven by |
|---|---|---|
| Token-aware sliding-window rate limiter, e.g. 50,000 tokens/min per tenant API key | `ratelimit.py` (`TokenRateLimiter`), wired in through Task 3's `create_app(limiter=…)` | `test_ratelimit.py`; e2e concurrent requests; live test against real Claude |
| Primary returns **429** or **times out after 3000 ms** → fail over to a backup provider | `router.py` (`FailoverProvider`), `openai_provider.py` | `test_router.py` (real asyncio timing); e2e: 429 failover, hang → failover at 3.0 s; live failover to real OpenAI |
| Standardized gateway error payload, no upstream stack traces or internals | Task 3's envelope `{"error":{message,type,code,param,request_id}}` on every path | e2e: both providers failing, 529, budget errors; no hostnames, SDK text or tracebacks |
| On-disk SQLite | `var/ratelimit.sqlite3` (WAL) | `test_state_is_on_disk_and_survives_restart`, e2e reads the file |

## Run it

From the repo root, with `.env` filled in (copy `.env.example`; the required
values are `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `LLM_GATEWAY_API_KEYS`):

```bash
uv sync
uv run python -m task4_model_router      # :8090, configured by .env
```

The gateway reads `LLM_GATEWAY_*`, `LLM_ROUTER_*`, both provider keys and
`LOG_*` from `.env` (or the environment, which wins). It refuses to start,
naming the variable, if either provider key is missing: without the backup's
key the first failover would fail. A misspelled `LLM_GATEWAY_*` or
`LLM_ROUTER_*` name is refused the same way.

Same endpoint and client as Task 3 (`POST /v1/chat/completions`,
OpenAI-compatible). Every response says who served it and what budget is
left: `x-gateway-provider`, `x-ratelimit-limit-tokens`,
`x-ratelimit-remaining-tokens`.

Offline: run `python -m task3_pii_guardrail.mock_provider --port 9090` and
`python -m task4_model_router.mock_openai --port 9092`, and set
`LLM_GATEWAY_ANTHROPIC_BASE_URL=http://127.0.0.1:9090` and
`LLM_ROUTER_OPENAI_BASE_URL=http://127.0.0.1:9092/v1` in `.env` (the provider
keys can then be any non-empty value). In a prompt, `[[status:429]]`,
`[[hang:6]]`, `[[status:529]]` and `[[openai:429]]` script the primary's and
backup's behaviour.

### A real session (offline mocks; scripted by the markers above)

| Request | Result | Served by | Time |
|---|---|---|---|
| healthy primary (`mail a@b.io`) | 200 `You said: hello, mail [REDACTED]` | anthropic | 0.04 s |
| primary 429 | 200 `Backup says: card [REDACTED]` | **openai** | 0.03 s |
| primary hangs 6 s | 200 `Backup says: are you there` | **openai** | **3.01 s** |
| both providers 429 | 429 `rate_limit_error`, backup's `Retry-After: 4` passed through | none | immediate (backup SDK retries are 0) |
| primary 529 | 502 `provider_error`, **no failover** (see Decisions) | none | 0.002 s |

Audit log for that session: `llm.failover` with `reason: rate_limited`, then
`reason: timeout`; `llm.response_redaction` with a count. No values, no
internals.

### Live, with your keys

Run with `RUN_LIVE_TESTS=1`; the keys are read from `.env`, and it costs a
fraction of a cent:

| Test | Result |
|---|---|
| Real Claude primary + real rate limit (60-token budget) | `200, 200, 429`: the gateway refused the third call itself. Both rows settled to the provider's real usage (22 tokens each, not the 28 reserved) |
| Primary forced to 429 → **real OpenAI `gpt-6.1-sol`** | 200, `x-gateway-provider: openai`, email redacted |

## Decisions

| Question | Decision | Why |
|---|---|---|
| What triggers failover? | **Exactly** a primary 429 or the 3000 ms timeout | The brief names those two. Outages (5xx/529) and rejected requests return the standard error instead. Widening the set is a one-line change (`FAILOVER_ON`). |
| What does "times out after 3000 ms" measure? | Time until the primary **answers**: its HTTP response begins (`Started`) | A model that is *thinking* before its first token has answered. Counting thinking time would fail over healthy requests. |
| Fail over mid-answer? | **No** | The client may already have text. Switching providers would splice two different responses. The stream ends with the standard error event. |
| SDK retries (primary and backup) | **0** | A primary retry would sleep inside the 3 s budget and delay failover. A backup retry would sleep inside the backup deadline and turn the backup's 429 + `Retry-After` into a 504. |
| Backup model | `gpt-6.1-sol` (your choice) | Checked with a 16-token streaming call before building on it. |
| Default budget | 50,000 tokens/min per API key (the brief's example) | Override with `LLM_ROUTER_TOKENS_PER_MINUTE`. |

## Design, and why

### Rate limiter (`ratelimit.py`)

- **True sliding window.** Each admitted request is a row
  `(tenant, ts, tokens)`, and usage is the sum over the last 60 s *from now*.
  There's no bucket edge where a tenant could spend 2× the limit across a
  boundary.
- **Reserve, then settle.** Before calling a provider, the gateway reserves
  the request's worst case: estimated prompt plus `max_tokens`. The prompt
  estimate counts ASCII at ~4 chars/token, every non-ASCII character as a
  full token (CJK is often ~1 token per character), and 4 tokens of framing
  per message. That is a near-upper bound for common text, not a guarantee
  for every tokenizer. When
  the response ends, the row is rewritten to the provider's **real** usage
  (`Usage` from Anthropic's `message_start`/`message_delta`, or OpenAI's
  usage chunk). It becomes an estimate if no usage was reported, or **0** if
  no provider served the request. The window therefore holds real usage.
  Live, the reservation was 28 and the settled value 22.
- **Atomic under concurrency.** Check-and-insert runs in one
  `BEGIN IMMEDIATE` transaction, which takes SQLite's write lock up front. 100
  concurrent requests admit exactly `limit / size`, both through one
  connection and **across two connections sharing the file** (separate
  gateway workers). DB calls run in a worker thread, so the event loop never
  blocks on disk.
- **Eviction.** Each check deletes that tenant's expired rows. A periodic
  global sweep clears tenants that went quiet, so the table holds about one
  window of rows.
- **Settlement can't be lost.** It runs in its own task behind
  `asyncio.shield`, so a client disconnecting mid-stream (Starlette cancels
  the response body and re-cancels cleanup awaits) can't drop it, and its
  errors are logged without touching the response. A limiter *error* on
  admission (e.g. a locked database) fails closed with a 503.
- **Concurrent startup.** Several workers opening the same file at once is
  safe: the switch to WAL mode is retried with backoff (it needs an exclusive
  lock and fails instantly under contention).
- **Precise `Retry-After`:** the time until enough of the oldest rows expire
  (rounded up, never early). A request bigger than the whole budget gets an
  immediate **400** `request_exceeds_token_budget`, because waiting can never
  help.

### Router (`router.py`)

- **Cancel the losing side.** `asyncio.timeout` cancels the pending primary
  call at 3000 ms; the SDK aborts the HTTP request and the generator is
  closed. The tests assert the primary is cancelled, not left running beside
  the backup.
- **The boundary is exact:** a primary that answers at 2.9 s is kept even if
  its text is slow afterwards. One that hasn't answered by 3.0 s is dropped.
- **Closing the losing or finished stream can't be cut off.** On a client
  disconnect, Starlette's anyio cancellation cancels every await in cleanup
  again. The router's and the OpenAI provider's closes run in
  `close_shielded()` (Task 3), so the HTTP stream to the provider is closed,
  not abandoned. A test closes the router inside a cancelled scope and checks
  that the provider's close completes.
- **The backup has its own deadline** (`LLM_ROUTER_BACKUP_TIMEOUT_S`), so a
  double failure ends in a bounded time with the standard error.
- `FailoverProvider` is itself a `Provider`. Task 3's gateway, redaction and
  error handling apply to whichever provider served, unchanged.

### Errors

Everything goes through Task 3's single OpenAI-shaped envelope plus
`request_id`, with internals kept in the log.

| Situation | HTTP | `type` / `code` |
|---|---|---|
| Tenant over budget | 429 + `Retry-After` + `x-ratelimit-*` | `rate_limit_error` / `token_rate_limit_exceeded` |
| Request larger than the whole budget | 400 | `invalid_request_error` / `request_exceeds_token_budget` (`param: max_tokens`) |
| Both providers rate-limited | 429 + `Retry-After` | `rate_limit_error` |
| Primary outage (no failover) / both down | 502 | `provider_error` |
| Provider timed out | 504 | `provider_error` |
| Rate limiter itself unavailable (e.g. database locked) | 503 (request denied) | `service_unavailable` |

## Tests

```bash
uv run pytest task4-model-router -q
RUN_LIVE_TESTS=1 uv run pytest task4-model-router -m live      # keys read from .env, ~5 tiny calls
```

| Suite | Tests | What it proves |
|---|---|---|
| `test_ratelimit.py` | 18 | Sliding (not fixed) window; exact `Retry-After`; settle up and down, refund; tenant isolation; eviction incl. idle tenants; on-disk persistence across restart; **no over-admission under concurrency: one connection, two connections, and 4 real processes**; hostile tenant ids are just data |
| `test_router.py` | 13 | Healthy primary; 429 failover with audit; **timeout failover at the deadline with the primary cancelled**; answering just before the deadline is kept; no failover on other errors or mid-stream; both fail; backup timeout; early close; close completes inside a cancelled scope; 20 concurrent mixed requests |
| `test_openai_provider.py` | 5 | The real OpenAI SDK against the mock: event order, gateway-chosen model, `max_completion_tokens`, usage reporting, error mapping |
| `test_router_e2e.py` | 8 (+2 live) | **Three real processes over real sockets**: all of the above end to end, including redaction on the backup path and the SQLite file |
| `e2e/` (repo root) | | The gateway with every setting from a `.env` file (a non-default budget proves it was read); PII from an MCP tool redacted on both provider paths; the standard 429; startup refusal when a provider key is missing |

## Known limitations

- **Estimated reservations.** Reservations are estimates corrected at
  settlement. An unusual tokenizer or input could still under-count one
  request (over-spend is then bounded by the request body limit), and a large
  `max_tokens` can be refused early when the budget is nearly spent.
- **One backup.** No chain of providers or health-based routing.
- **Wall-clock window.** Separate gateway processes sharing the SQLite file
  must have roughly synchronised clocks (normal NTP is fine).
