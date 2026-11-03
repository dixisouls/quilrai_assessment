# CLAUDE.md — QuilrAI Assessment (AI Field Developer / Solutions Engineer)

This file governs all work in this repo. Read it fully before touching code.
The assessment brief is `ASSESSMENT.md`. Mistakes are logged in `MISTAKES.md`.

Every component must be **secure by default, fail closed, auditable, low
latency, and honest about its limits.**

| Task | What it is |
|---|---|
| 1. MCP server (stdio, strict validation) | A well-behaved downstream MCP server (also served over HTTP for the gateway) |
| 2. MCP security gateway (RBAC on tools) | Per-tool authorization in front of an MCP server |
| 3. Streaming PII redaction | LLM gateway, response-path guardrail |
| 4. Token rate limiter + model fallback | LLM gateway, rate limits and routing/failover |

---

## 1. Non-negotiable working rules

0. **Delivery routine: follow `CONTRIBUTING.md`.** Branch per task
   (`task/N-<slug>`), small commits, CI green, then a **fresh independent
   reviewer agent** (no shared context) reviews the diff before the PR. Fix the
   findings, then merge into `main` via PR. Never commit to `main` directly.
1. **Part by part.** One task at a time, in order. At the end of each task: all
   tests green, README written, mistakes logged, then **stop and hand back to the
   user for review** before starting the next task.
2. **Tests first (TDD).** Write the failing test, watch it fail, then implement.
   Every task has:
   - **Unit tests** — pure logic (validators, regex/buffer state machine,
     sliding window math, error mappers, role resolution).
   - **Integration tests** — real processes / real sockets: spawn the stdio
     server as a subprocess and speak raw JSON-RPC; run the gateway against a
     real downstream server; run the LLM gateway against a mock upstream over HTTP.
   - **Security / negative tests** — malformed JSON, wrong types, oversize
     bodies, missing/forged/expired tokens, privilege escalation attempts,
     PII split across chunk boundaries, timeout races, SQL-injection-shaped keys.
   - **End-to-end tests** — the combined system (see §3).
   - Live tests against real providers are marked `@pytest.mark.live` and skip
     automatically when the API key env var is absent. Default `pytest` run is
     offline and deterministic.
3. **Evidence before claims.** Never say "done", "works", or "passes" without
   having run the command in this session and seen the output. Report failures
   verbatim.
4. **No corner cutting.** No `TODO: handle later` on a security path. No
   swallowed exceptions. No `# type: ignore` / `noqa` without a written reason.
   If something is out of scope, it is documented in the README under
   "Known limitations", not silently skipped.
5. **Log mistakes.** Any bug we introduced, wrong assumption, failed approach,
   or spec misread goes in `MISTAKES.md` (what happened → root cause → fix →
   how we prevent it). Honesty here is a feature, not a weakness.
6. **Original work only.** Public repos exist that attempt this exact
   assessment (e.g. on GitHub under "QuilrAI_MCP"). **Do not read, copy, or
   adapt them.** Official docs/specs/SDK sources are fine and should be cited.
7. **Verify library APIs, don't guess.** The `mcp` Python SDK has had breaking
   major versions (1.x → 2.x). Check the installed version's actual API/source
   before writing against it. Pin versions.
8. **Ask, don't assume,** when a decision changes behaviour a reviewer will see
   (e.g. which real LLM provider to use, token format). Record the decision in
   the task README.

---

## 2. Security rules (apply to every line of code)

### Fail closed / deny by default
- Unknown role, missing token, unparseable token, unknown method on a guarded
  path, guardrail error, rate-limiter DB error → **deny**, never allow.
- The only fail-open behaviour allowed must be explicit, configurable, documented
  in the README, and default to off.

### Authentication & authorization
- Tokens are **verified**, not decoded: signed JWTs with an algorithm allowlist
  (never `alg: none`), required `exp`, `iss`, `aud`, and a role claim validated
  against an enum. Any static-token mode for local dev uses constant-time
  comparison (`hmac.compare_digest`).
- Authorization is decided **at the gateway, before** any downstream call.
  Denied requests must provably never reach downstream (tests assert the
  downstream received zero calls).
- Least privilege: roles map to explicit allowed capabilities; new tools are
  not implicitly granted. Tool-name checks must be robust to case, whitespace,
  unicode look-alikes, and JSON-RPC batch smuggling.

### Input validation
- Validate every boundary with Pydantic (strict mode, `extra="forbid"`).
  Reject, don't coerce (`"12"` is not a float; `true` is not a number;
  `NaN`/`Infinity` are not amounts).
- Enforce **request body size limits**, max JSON depth, max batch size, max
  string lengths. Unbounded input is a DoS.
- Money is `Decimal`, never float arithmetic. Bound and quantize it.

### Errors & information leakage — "tell the caller what *they* can fix"
Clients **do** get useful errors. What they never get is *our internals*. The
split follows who can act on the information:

| Situation | Client receives | Stays in logs only (by `request_id`) |
|---|---|---|
| Bad input (4xx) | Exactly what's wrong: field path, the violated rule, how to fix it | The rejected *value* (may be PII); we don't echo it back |
| AuthN failure (401) | `invalid_token` plus a short reason (`expired`, `malformed`), per RFC 6750 | Which check failed in detail (signature, issuer, kid) |
| AuthZ failure (403 / -32001) | Which tool or action was denied and the role required | Policy evaluation trace |
| Rate limited (429) | Limit, remaining, `Retry-After`, `X-RateLimit-*` headers | Per-tenant counters |
| Upstream/internal (5xx) | Generic message + stable code + `request_id` | Stack trace, provider error body, hostnames, SQL, timings |

- Every response carries `X-Request-ID`, and every error body carries
  `request_id`. Support pastes that ID to find the full detail in the logs.
  That is the industry pattern (Stripe, OpenAI, Google AIP-193).
- **One envelope per protocol** (each defined once, in the service that speaks it):
  - LLM gateway (OpenAI-compatible): the OpenAI error shape
    `{"error": {"message", "type", "code", "param", "request_id"}}`, so
    existing OpenAI/Anthropic-style SDKs parse it unchanged.
  - MCP gateway / server: the JSON-RPC 2.0 error object
    `{"code", "message", "data": {"request_id", "details"?}}`.
    Spec codes: `-32700` parse, `-32600` invalid request, `-32601` method not
    found, `-32602` invalid params, `-32603` internal. Application codes use
    the `-32000..-32099` range (e.g. `-32001` Unauthorized Tool Call). Always
    echo the request `id` (`null` if unparseable).
  - Other HTTP endpoints: RFC 9457 Problem Details (`application/problem+json`).
- Never in a response: stack traces, upstream bodies, hostnames, file paths,
  SQL, library names, provider names/keys (unless intentionally exposed).

### Logging & audit (implemented in `common/src/quilr_common/log/`)
- **stdout is sacred** for stdio MCP servers: JSON-RPC only. Use
  `configure_logging(..., stdout_reserved=True)`; it refuses stdout sinks.
  `print()` is banned by ruff `T20`.
- One JSON object per line: `ts`, `level`, `logger`, `msg`, `service`,
  `request_id`/`tenant_id`/`principal` (from `bind_context`), extras, `exc`.
- Every security decision calls `emit_audit(AuditEvent(...))`. Audit events
  bypass `LOG_LEVEL` and are optionally written to an HMAC-keyed, hash-chained
  file (`LOG_AUDIT_PATH`, `LOG_AUDIT_HMAC_KEY`), checked with `verify_chain`.
- **Never log secrets or PII.** Redaction runs centrally in the formatter and
  covers messages, extras, context, stack traces and fallback paths. Call
  sites still log IDs, lengths and hashes rather than raw prompts or tool
  arguments.
- **Where logs go (12-factor):** services write the event stream to
  stdout/stderr and never manage log files. In a container deployment, a log
  shipper collects that output and routes it to storage and search, and the
  audit chain file lives on its own volume.

### Secrets & config
- Secrets only via environment variables / `.env` (git-ignored). A committed
  `.env.example` documents every variable with fake values, marking which are
  required and showing the default of the rest.
- **How configuration is loaded:** every entrypoint uses
  `quilr_common.config.load_settings()`. Real environment variables come
  first, then `.env` (read by the service itself; `QUILR_ENV_FILE` overrides
  the path), then class defaults.
  - Each settings class has its own prefix, `extra="forbid"` and
    `dotenv_filtering="match_prefix"`, so one shared `.env` works and typos
    fail at startup.
  - Secrets have no defaults: they are required.
  - Never set `env_file` on a settings class, because tests would then read
    the developer's file. The root `conftest.py` turns file loading off for
    the test run.
  - Configuration errors name the variable and never echo its value.
- No secrets in tests, fixtures, logs, or commit history. Test keys are
  generated at test time.

### Network & resilience
- Every outbound call has an explicit timeout. No unbounded retries.
- Cancel the losing side of any timeout race; no leaked tasks or connections.
- Upstream URLs are configuration, never derived from client input (no SSRF).
- Proxies strip hop-by-hop headers and never forward the client's gateway
  token to downstream/upstream services.

### Data
- SQLite: parameterized queries only, WAL mode, explicit transactions for
  read-modify-write (rate limiter must be atomic under concurrency).
- PII redaction must not hold the full response in memory; bounded buffers only.

### Dependencies
- Minimal, well-known, pinned. Justify each in the task README.
  Run `pip-audit` before each task is closed.

---

## 3. "Works together" — target architecture

Each task lives in its own folder and runs standalone, **and** the pieces
compose into one system with a real end-to-end path:

```
                     ┌───────────────────────── LLM Gateway ─────────────────────────┐
 client / agent ───► │ auth → token rate limit (T4, SQLite) → router/failover (T4)   │ ──► real LLM provider(s)
                     │                     ◄── streaming PII redaction (T3) ◄──       │     (+ mock for tests)
                     └───────────────────────────────────────────────────────────────┘

                     ┌──── MCP Security Gateway (T2) ────┐
 agent ────────────► │ JWT auth → JSON-RPC inspect → RBAC │ ──► T1 tools over HTTP (task1_mcp_server.serve_http)
                     └────────────────────────────────────┘     (T1's brief transport, stdio, runs standalone)
```

- Shared code (settings loading, logging/audit, redaction) lives in the
  `common/` package — written once, tested once.
- The root `e2e/` suite starts every service as a real process, configured
  only by a `.env` file, and exercises the combined flow. Docker packaging is
  out of scope (decided with the user).
- "Real working" means: real processes, real sockets, real SQLite file on
  disk, and a real LLM provider path (key via env). Mocks exist so tests are
  deterministic and so graders can run without keys — they are not a
  substitute for the real path.

---

## 4. Repo conventions

- **Python 3.12**, `asyncio` throughout, type hints everywhere, `mypy --strict`
  clean, `ruff` (lint + format) clean.
- Layout (finalised in the scaffold step):
  ```
  common/              shared library (quilr_common)
  task1-mcp-server/    src + tests + README.md (package task1_mcp_server)
  task2-mcp-gateway/
  task3-pii-guardrail/
  task4-model-router/
  e2e/                 cross-task end-to-end tests
  conftest.py          test-run setup (.env loading off)
  MISTAKES.md
  ```
- Each task README has: **What it does → How to run → Design & why this
  approach (with alternatives considered and rejected) → Security
  considerations → Test strategy & how to run tests → Known limitations.**
- **Commit early and often** (standing instruction): small, incremental
  commits, one logical change each, so any step can be reverted. Commit a unit
  once its tests pass; never leave `main` red.
- Conventional Commits: `type(scope): short imperative title` (≤ 72 chars),
  blank line, then an extended body explaining **what and why**.
  Types: `feat`, `fix`, `test`, `docs`, `refactor`, `build`, `chore`, `ci`,
  `perf`, `security`. Scopes: `common`, `task1`..`task4`, `e2e`, `repo`.
- **No AI attribution in commits**: no `Co-Authored-By` trailer, no
  "generated with" lines, no mention of AI tooling.
- Never commit secrets, `.env`, SQLite files, or logs. Review
  `git status` and `git diff --cached` before every commit.

## 5. Definition of done (per task)

- [ ] All requirements in `ASSESSMENT.md` for the task are met, line by line.
- [ ] Unit + integration + security-negative tests written and passing.
- [ ] `make check` clean locally; all CI checks green on the branch.
- [ ] Independent reviewer agent run; findings fixed or rebutted.
- [ ] Ran it for real (not only tests) and captured the output in the README.
- [ ] README complete, including "why this approach".
- [ ] `MISTAKES.md` updated.
- [ ] Handed back to the user for review.
