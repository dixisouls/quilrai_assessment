# CLAUDE.md — QuilrAI Assessment (AI Field Developer / Solutions Engineer)

This file governs all work in this repo. Read it fully before touching code.
The assessment brief is `ASSESSMENT.md`. Mistakes are logged in `MISTAKES.md`.

---

## 1. Context: who we are building for

**QuilrAI** (quilr.ai) is an AI security & compliance company (Austin / Pune, founded 2024).
Their product is exactly what this assessment asks us to build in miniature:

- **LLM Gateway** — OpenAI-compatible, one `base_url` change. Pipeline:
  Identity/Auth → Rate limits & token budgets → Security guardrails (PII/PHI/PCI,
  prompt injection) → Custom intents → Prompt store → Token saving → Routing/failover.
  Controls apply on **both** request and response paths.
- **MCP Gateway** — transparent proxy between agents and MCP servers. Per-tool
  permissions, least privilege, tool risk tiers (read / write / destructive —
  destructive disabled by default), auth mediation (agents never see raw creds),
  scans tool outputs for injection, logs every tool invocation.
- **Claims they sell on:** < 50 ms enforcement overhead, immutable audit logs,
  SOC 2 Type II, HIPAA, PCI-DSS, NIST AI RMF alignment.

**Implication:** reviewers are security engineers. They will judge us on the
things their product promises. Every component must be **secure by default,
fail closed, auditable, low latency, and honest about its limits.**

| Task | Maps to QuilrAI product surface |
|---|---|
| 1. MCP server (stdio, strict validation) | A well-behaved downstream MCP server |
| 2. MCP security gateway (RBAC on tools) | MCP Gateway — per-tool authorization |
| 3. Streaming PII redaction | LLM Gateway — response-path guardrail |
| 4. Token rate limiter + model fallback | LLM Gateway — rate limits + routing/failover |

---

## 2. Non-negotiable working rules

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
   - **End-to-end tests** — the combined system (see §4).
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

## 3. Security rules (apply to every line of code)

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

### Errors & information leakage
- Clients receive a **standardized error payload** only: stable code, safe
  message, and a request/correlation ID. Never stack traces, upstream bodies,
  hostnames, file paths, SQL, library names, or provider API keys.
- JSON-RPC errors use spec codes: `-32700` parse, `-32600` invalid request,
  `-32601` method not found, `-32602` invalid params, `-32603` internal;
  application codes in the `-32000..-32099` server range (e.g. `-32001`
  Unauthorized Tool Call). Always echo the request `id` (or `null` if
  unparseable).

### Logging & audit
- **stdout is sacred** for stdio MCP servers: JSON-RPC only. All logs → stderr.
  No `print()` anywhere in library code (enforced by a lint rule and a test).
- Structured JSON logs. Every security decision (allow/deny/redact/rate-limit/
  failover) emits an audit event with: timestamp, request ID, principal/tenant,
  action, decision, reason.
- **Never log secrets or PII**: no tokens, API keys, raw prompts/completions,
  or unredacted tool arguments. Log hashes/IDs/lengths instead. Log redaction
  is applied as a logging filter, not left to each call site.

### Secrets & config
- Secrets only via environment variables / `.env` (git-ignored). A committed
  `.env.example` documents every variable with fake values.
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

## 4. "Works together" — target architecture

Each task lives in its own folder and runs standalone, **and** the pieces
compose into one system with a real end-to-end path:

```
                     ┌───────────────────────── LLM Gateway ─────────────────────────┐
 client / agent ───► │ auth → token rate limit (T4, SQLite) → router/failover (T4)   │ ──► real LLM provider(s)
                     │                     ◄── streaming PII redaction (T3) ◄──       │     (+ mock for tests)
                     └───────────────────────────────────────────────────────────────┘

                     ┌──── MCP Security Gateway (T2) ────┐
 agent ────────────► │ JWT auth → JSON-RPC inspect → RBAC │ ──► MCP server (T1 tools, HTTP transport)
                     └────────────────────────────────────┘     (T1 also runs standalone over stdio)
```

- Shared code (error envelope, JSON-RPC models, logging/audit, auth/JWT,
  config) lives in a `common/` package — written once, tested once.
- A root-level `docker-compose.yml` / Makefile target brings the whole system
  up; a root `e2e/` test suite exercises the combined flow.
- "Real working" means: real processes, real sockets, real SQLite file on
  disk, and a real LLM provider path (key via env). Mocks exist so tests are
  deterministic and so graders can run without keys — they are not a
  substitute for the real path.

---

## 5. Repo conventions

- **Python 3.12**, `asyncio` throughout, type hints everywhere, `mypy --strict`
  clean, `ruff` (lint + format) clean.
- Layout (finalised in the scaffold step):
  ```
  common/              shared library
  task1_mcp_server/    src + tests + README.md
  task2_mcp_gateway/
  task3_pii_guardrail/
  task4_model_router/
  e2e/                 cross-task end-to-end tests
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
  `perf`, `security`. Scopes: `common`, `task1`..`task4`, `e2e`, `docker`, `repo`.
- **No AI attribution in commits**: no `Co-Authored-By` trailer, no
  "generated with" lines, no mention of AI tooling.
- Never commit secrets, `.env`, SQLite files, or logs. Review
  `git status` and `git diff --cached` before every commit.

## 6. Definition of done (per task)

- [ ] All requirements in `ASSESSMENT.md` for the task are met, line by line.
- [ ] Unit + integration + security-negative tests written and passing.
- [ ] `ruff`, `mypy --strict`, `pip-audit` clean.
- [ ] Ran it for real (not only tests) and captured the output in the README.
- [ ] README complete, including "why this approach".
- [ ] `MISTAKES.md` updated.
- [ ] Handed back to the user for review.
