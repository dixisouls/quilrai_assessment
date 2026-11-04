# AI Field Developer / Solutions Engineer assessment

Python solutions to the four tasks in [`ASSESSMENT.md`](ASSESSMENT.md). Each
task runs on its own, and they compose into one system:

```
                ┌──────── MCP security gateway (Task 2) ────────┐
 agent ───────► │ JWT auth → strict JSON-RPC parse → tool RBAC  │ ───► MCP server (Task 1)
                └───────────────────────────────────────────────┘      customer tools over HTTP
                                                                       (stdio when run standalone)

                ┌──────────── LLM gateway (Tasks 3 + 4) ────────────┐
 client ──────► │ API key → token rate limit (SQLite) → failover     │ ───► Anthropic (primary)
                │                                                    │ ───► OpenAI (backup, on 429 / 3 s)
          ◄──── │ streaming PII redaction on the response            │
                └────────────────────────────────────────────────────┘
```

| Task | Folder | What it does |
|---|---|---|
| 1. MCP server, strict validation | [`task1-mcp-server/`](task1-mcp-server/README.md) | `get_customer_record` and `trigger_refund` on the official MCP SDK. Pydantic strict validation, standard JSON-RPC errors, stdout reserved for JSON-RPC |
| 2. MCP security gateway | [`task2-mcp-gateway/`](task2-mcp-gateway/README.md) | Reverse proxy: signed-JWT roles, `admin_*` tools refused with `-32001` before anything reaches downstream |
| 3. Streaming PII guardrail | [`task3-pii-guardrail/`](task3-pii-guardrail/README.md) | OpenAI-compatible endpoint that redacts emails, SSNs and card numbers from the response *while it streams*, with a bounded buffer |
| 4. Rate limit + failover | [`task4-model-router/`](task4-model-router/README.md) | Token-aware sliding-window limiter on on-disk SQLite; fails over to the backup on a 429 or a 3000 ms timeout; one standard error payload |
| Shared | [`common/`](common/README.md) | Settings loading (`.env`), structured JSON logging with redaction, tamper-evident audit trail |

Each task README covers what it does, how to run it, the design and why
(with the alternatives rejected), security considerations, tests, and known
limitations.

## Run it

Requirements: Python 3.12 and [uv](https://docs.astral.sh/uv/) 0.13.6. Run
everything from the repo root.

```bash
uv sync
cp .env.example .env        # then fill in the REQUIRED values at the top
```

Each service reads `.env` itself at startup; no `source` is needed. Real
environment variables override it. A missing or misspelled setting stops the
service with a message naming the variable (never its value).
[`.env.example`](.env.example) lists every setting, marked required or shown
with its default.

**MCP side (Tasks 1 + 2):**

```bash
uv run python -m task2_mcp_gateway.devtokens keygen --dir var/keys     # once; stands in for an IdP
uv run python -m task1_mcp_server.serve_http &                          # Task 1 tools on :8000
uv run python -m task2_mcp_gateway &                                    # gateway on :8080
TOKEN=$(uv run python -m task2_mcp_gateway.devtokens mint --role viewer --sub alice)
# MCP client → http://127.0.0.1:8080/mcp with "Authorization: Bearer $TOKEN"
```

Task 1 on its own, over stdio as the brief asks: `uv run python -m task1_mcp_server`.

**LLM side (Tasks 3 + 4):**

```bash
uv run python -m task4_model_router        # :8090, OpenAI-compatible
curl -N http://127.0.0.1:8090/v1/chat/completions \
  -H "authorization: Bearer <one of LLM_GATEWAY_API_KEYS>" -H 'content-type: application/json' \
  -d '{"model":"claude-opus-5-5","stream":true,"messages":[{"role":"user","content":"Hi"}]}'
```

Task 3 on its own (no rate limit, no failover): `uv run python -m task3_pii_guardrail`.

**Without provider keys:** start the mocks and point the gateway at them in
`.env` (the provider keys can then be any non-empty value):

```bash
uv run python -m task3_pii_guardrail.mock_provider --port 9090 &   # LLM_GATEWAY_ANTHROPIC_BASE_URL=http://127.0.0.1:9090
uv run python -m task4_model_router.mock_openai --port 9092 &     # LLM_ROUTER_OPENAI_BASE_URL=http://127.0.0.1:9092/v1
```

## Tests

```bash
make check                                  # everything CI runs: lint, mypy --strict, tests, security scans
uv run pytest                               # tests only, offline and deterministic
RUN_LIVE_TESTS=1 uv run pytest -m live      # a few tiny real-provider calls; keys from .env
```

- **Per task:** unit, integration (real processes on real sockets) and
  security-negative tests.
- **[`e2e/`](e2e):** every service as a real process, configured *only* by a
  `.env` file the test writes:
  - agent → MCP gateway → Task 1's real tools;
  - customer PII from a tool redacted on the LLM response, on both the
    primary and the backup path;
  - the standard 429 from the rate limiter;
  - startup refused on bad configuration.
- **Not affected by your `.env`:** the test run turns `.env` loading off
  (`conftest.py`), so your local file can't change the results.

## How this was built

- **Process ([`CONTRIBUTING.md`](CONTRIBUTING.md)):**
  - one branch per task, small conventional commits;
  - CI gates: lint, strict typing, tests with a 90% coverage gate, pip-audit,
    gitleaks, CodeQL, a Trojan Source scan;
  - an independent reviewer agent on every branch before merge.
- **[`MISTAKES.md`](MISTAKES.md)** logs every bug, wrong assumption and
  review finding: what happened, root cause, fix, prevention.
- **Known limitations** are listed at the end of each README rather than left
  out. Docker packaging is out of scope.
