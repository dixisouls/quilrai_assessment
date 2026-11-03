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

```bash
uv sync
set -a && source .env && set +a          # ANTHROPIC_API_KEY, OPENAI_API_KEY
export CLIENT_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
LLM_GATEWAY_API_KEYS="[\"$CLIENT_KEY\"]" uv run python -m task4_model_router     # :8090
```

Same endpoint and client as Task 3 (`POST /v1/chat/completions`,
OpenAI-compatible). Every response says who served it and what budget is
left: `x-gateway-provider`, `x-ratelimit-limit-tokens`,
`x-ratelimit-remaining-tokens`.

Offline: `python -m task3_pii_guardrail.mock_provider --port 9090` and
`python -m task4_model_router.mock_openai --port 9092`, with
`LLM_GATEWAY_ANTHROPIC_BASE_URL=http://127.0.0.1:9090` and
`LLM_ROUTER_OPENAI_BASE_URL=http://127.0.0.1:9092/v1`. In a prompt,
`[[status:429]]`, `[[hang:6]]`, `[[status:529]]` and `[[openai:429]]` script
the primary's and backup's behaviour. All settings are in `.env.example`.

### A real session (offline mocks; scripted by the markers above)

| Request | Result | Served by | Time |
|---|---|---|---|
| healthy primary (`mail a@b.io`) | 200 `You said: hello, mail [REDACTED]` | anthropic | 0.04 s |
| primary 429 | 200 `Backup says: card [REDACTED]` | **openai** | 0.03 s |
| primary hangs 6 s | 200 `Backup says: are you there` | **openai** | **3.01 s** |
| both providers 429 | 429 `rate_limit_error`, `Retry-After: 4` | none | 4.0 s (backup's one SDK retry honoured `Retry-After`) |
| primary 529 | 502 `provider_error`, **no failover** (see Decisions) | none | 0.002 s |

Audit log for that session: `llm.failover` with `reason: rate_limited`, then
`reason: timeout`; `llm.response_redaction` with a count. No values, no
internals.

### Live, with your keys

Run with `RUN_LIVE_TESTS=1`; it costs a fraction of a cent:

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
| Primary's SDK retries | **0** | Otherwise the SDK retries the 429 itself (with backoff) inside the 3 s budget, which delays failover. |
| Backup model | `gpt-6.1-sol` (your choice) | Checked with a 16-token streaming call before building on it. |
| Default budget | 50,000 tokens/min per API key (the brief's example) | Override with `LLM_ROUTER_TOKENS_PER_MINUTE`. |

## Design, and why

### Rate limiter (`ratelimit.py`)

- **True sliding window.** Each admitted request is a row
  `(tenant, ts, tokens)`, and usage is the sum over the last 60 s *from now*.
  There's no bucket edge where a tenant could spend 2× the limit across a
  boundary.
- **Reserve, then settle.** Before calling a provider, the gateway reserves
  the request's worst case: estimated prompt (~4 chars/token) plus
  `max_tokens`. That can't under-count while the response is unknown. When
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

## Tests

```bash
uv run pytest task4-model-router -q
RUN_LIVE_TESTS=1 uv run pytest task4-model-router -m live      # real keys from .env, ~5 tiny calls
```

| Suite | Tests | What it proves |
|---|---|---|
| `test_ratelimit.py` | 17 | Sliding (not fixed) window; exact `Retry-After`; settle up and down, refund; tenant isolation; eviction incl. idle tenants; on-disk persistence across restart; **no over-admission under concurrency, also across two connections**; hostile tenant ids are just data |
| `test_router.py` | 12 | Healthy primary; 429 failover with audit; **timeout failover at the deadline with the primary cancelled**; answering just before the deadline is kept; no failover on other errors or mid-stream; both fail; backup timeout; early close; 20 concurrent mixed requests |
| `test_openai_provider.py` | 5 | The real OpenAI SDK against the mock: event order, gateway-chosen model, `max_completion_tokens`, usage reporting, error mapping |
| `test_router_e2e.py` | 8 (+2 live) | **Three real processes over real sockets**: all of the above end to end, including redaction on the backup path and the SQLite file |

## Known limitations

- **Prompt-size estimate.** The reservation uses ~4 chars per token. It is
  corrected at settlement, but a large `max_tokens` can be refused early
  when the budget is nearly spent. That is intentionally conservative.
- **One backup.** No chain of providers or health-based routing.
- **Wall-clock window.** Separate gateway processes sharing the SQLite file
  must have roughly synchronised clocks (normal NTP is fine).
