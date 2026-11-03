# quilr-common

The shared base used by every service in this repo: **settings loading
(environment + `.env`), structured JSON logging, sensitive-data redaction,
request context and a tamper-evident audit trail**. Each service defines its
own error envelope next to its protocol (JSON-RPC for the MCP services,
OpenAI-style for the LLM gateway).

## Usage

```python
from quilr_common.log import (
    AuditEvent,
    Decision,
    ServiceInfo,
    bind_context,
    configure_logging,
    emit_audit,
    get_logger,
    sanitize_request_id,
)

configure_logging(ServiceInfo(name="mcp-gateway", version="1.0.0", env="prod"))
log = get_logger(__name__)

with bind_context(
    request_id=sanitize_request_id(headers.get("x-request-id")),
    tenant_id="acme",
    principal="user-42",
):
    log.info("tool call received", extra={"tool": "admin_reset_key"})
    emit_audit(
        AuditEvent(
            action="tools.call",
            decision=Decision.DENY,
            reason="role 'viewer' may not call admin_* tools",
            resource="admin_reset_key",
        )
    )
```

Sample output (one line each, shown pretty-printed here):

```json
{"ts": "2026-10-30T14:02:11.418Z", "level": "INFO", "logger": "quilr.audit",
 "msg": "audit tools.call deny", "log_type": "audit",
 "request_id": "9f1c...", "tenant_id": "acme", "principal": "user-42",
 "audit": {"action": "tools.call", "decision": "deny", "resource": "admin_reset_key", ...},
 "service": {"name": "mcp-gateway", "version": "1.0.0", "env": "prod"}}
```

## Settings: environment variables plus `.env` (`quilr_common.config`)

Every entrypoint loads its settings the same way:

```python
from quilr_common.config import load_settings, service_info

configure_logging(service_info("llm-gateway", "0.2.0"), load_settings(LoggingSettings))
settings = load_settings(GatewaySettings)
```

| Source (highest priority first) | Notes |
|---|---|
| Real environment variables | How Docker, CI and orchestrators configure a process |
| The `.env` file | `./.env` by default, read by the service itself (no `source`). `QUILR_ENV_FILE` names another file, which must exist; an empty value turns file loading off |
| Defaults on the settings class | Secrets and values with no safe default have none, so they are required |

- **One file for every service.** Each settings class reads only its own
  prefix (`dotenv_filtering="match_prefix"`), and an unknown variable *with*
  that prefix (`LLM_GATEWAY_PROT`) is rejected at startup.
- **Errors say what to fix, never the value.** `ConfigError` is a
  `SystemExit`: the process exits with status 1 and prints only
  `configuration error: LLM_GATEWAY_API_KEYS.0: String should have at least
  16 characters`. No traceback, and no value (it may be a secret).
- **Only entrypoints read the file.** Settings classes don't name it, so code
  and tests that build settings directly never see a developer's `.env`. The
  repo's `conftest.py` also turns file loading off for every server the tests
  start.

Alternatives considered: `env_file=".env"` on each settings class (rejected:
every test that builds settings would silently read the developer's file),
and requiring `set -a; source .env` (what the repo did before: easy to forget,
and it silently started services on defaults; see `MISTAKES.md` F1).

## Logging configuration (`LOG_*`)

| Variable | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `INFO` | `DEBUG`…`CRITICAL`; audit events ignore it |
| `LOG_FORMAT` | `json` | `console` for human-readable local dev |
| `LOG_STREAM` | `stderr` | `stdout` is refused for stdio protocol servers |
| `LOG_AUDIT_PATH` | unset | Enables the hash-chained audit file |
| `LOG_AUDIT_HMAC_KEY` | unset | ≥ 32 chars; **required in production** (see threat model) |
| `LOG_AUDIT_FSYNC` | `true` | fsync each audit record |
| `LOG_MAX_FIELD_CHARS` | `8192` | Per-field cap against log flooding |

## Design, and why this approach

**The stdlib `logging` with our own formatter, not structlog or loguru.**
Every library in the stack (httpx, uvicorn, the MCP SDK) already logs through
stdlib `logging`. Owning the root handler gives all of them the same JSON
format and redaction with no adapters, and adds no dependency. The formatter
is about 150 lines and fully tested, so we control exactly what leaves the
process.

**Redaction in the formatter, not at call sites.** People forget, and a
central chokepoint can't be forgotten. Redaction runs on every field
(message, extras, bound context, stack traces), and it runs *before*
truncation so a cut can't split a secret in half and slip past the patterns.
Error and fallback paths, which skip formatters, get their own content-free
reporter (`fallback.py`), because the stdlib fallback echoes raw records
(see `MISTAKES.md` C3).

**Non-blocking with a queue and background thread.** QuilrAI's promise is
under 50 ms of enforcement overhead, so log I/O must never sit on the request
path. The bounded queue gives backpressure. App logs drop (and are counted)
under overload, while audit records block briefly and are reported if lost.
Losing an audit record is a security event; losing a debug line is not.

**`contextvars` for request context.** Each asyncio task gets its own copy,
so concurrent requests never mix request IDs. Thread-locals would be wrong
under asyncio. Context is captured on the calling thread before enqueueing,
because the listener thread can't see it.

**Audit events are validated models, not free-form log lines.** A fixed schema
(`action`, `decision` enum, `reason`, `principal`, `tenant_id`, `resource`,
`request_id`) gives the SIEM a stable contract. `extra="forbid"` stops schema
drift, and immutability stops events being altered after creation.

**Hash-chained audit file, keyed with HMAC.** QuilrAI sells immutable audit
logs. Each record commits to the previous one, so edits, deletions and
reordering are detectable.

| Threat | Unkeyed SHA-256 | HMAC-SHA256 (`LOG_AUDIT_HMAC_KEY`) |
|---|---|---|
| Accidental corruption / partial write | Detected | Detected |
| Edit or delete a record without recomputing | Detected | Detected |
| Attacker rewrites and recomputes the whole chain | **Not detected** | Detected (needs key) |
| Downgrade records to unkeyed hashes | n/a | Detected (alg is enforced) |
| Truncate the newest N records | Not detected | Not detected: anchor `head_hash` externally |

Alternatives considered: append-only storage such as S3 Object Lock or a WORM
bucket (the right *final* destination, but an infrastructure choice rather
than application code), a database table (needs triggers and permissions to
be append-only, which is harder to verify), and signing each record with
asymmetric keys (stronger non-repudiation, but key management is out of scope
here; HMAC is the pragmatic step).

**Where logs go.** Following the 12-factor approach, services write an event
stream to stdout/stderr and the platform routes it. In a container
deployment, a log shipper collects that output into searchable storage, and
the audit chain file sits on a dedicated volume readable only by its owning
service. (This repo doesn't include deployment files.)

## Redaction coverage

| Kind | Rule |
|---|---|
| Bearer tokens | `Bearer <token>`; the scheme word is kept |
| JWTs | `eyJ…` three-segment |
| Provider API keys | `sk-ant-…`, `sk-proj-…`, `sk-…` (20+ chars) |
| Emails | Practical RFC 5322 subset |
| US SSNs | `ddd-dd-dddd` / spaced; never-issued ranges excluded |
| Payment cards | 13–19 digits, optional space/dash groups, **Luhn-validated** |
| Sensitive keys | `authorization`, `api_key`, `password`, `cookie`, `token`, … (any value) |

## Tests

```bash
uv run pytest common -q --cov=quilr_common --cov-branch
```

139 tests:
- unit tests;
- Hypothesis properties (generated emails never survive, redaction is
  idempotent);
- concurrency (8 threads writing one chain, 20 interleaved asyncio tasks);
- attacker-view tamper tests (full-rewrite forgery, algorithm downgrade,
  spliced records, wrong key);
- a subprocess test proving stdout stays byte-empty;
- 14 settings-loading tests: file vs environment precedence, the shared file,
  typos, missing values, no echoed values.

## Known limitations

The logging package went beyond the brief, which never asks for one. The
items below came out of independent reviews #1 and #2 and are left as
documented limits, not fixed.

**Log redaction**
- **Slow on long unbroken input.** The email and JWT patterns backtrack
  quadratically on long runs with no match (100 KB took 7.8 s). Redaction
  runs on the logging thread, not the request path, but a flood of such
  lines backs up the queue: app logs are then dropped and counted. Task 3's
  response-path redactor is linear; this one hasn't been rewritten the same
  way.
- **Key-name matching misses some spellings.** camelCase and prefixed names
  (`accessToken`, `OPENAI_API_KEY`, `db_password`) aren't treated as
  sensitive keys. Their *values* are still caught when they match a pattern.
- **Pattern gaps.** A card number followed by its CVV, credentials in URL
  userinfo, `Basic`/`Token` auth headers, AWS/GitHub/Slack/Google key
  formats and `password=…` pairs aren't covered. "the bearer of bad news" is
  a false positive.
- **Only string length is bounded.** Container sizes and key lengths aren't.
- **Tracebacks.** Redaction runs on stack traces, but no dedicated test puts
  a secret in an exception's text.

**Logging pipeline and audit chain**
- **The listener's stream handler uses the stdlib `handleError`.** If writing
  a record fails, the stdlib can print that record, unredacted, to stderr.
- **Audit injection.** Any logger can inject a record into the audit chain by
  setting an `audit` attribute.
- **fsync failure.** If fsync fails after a write, the chain's in-memory state
  no longer matches the file.
- **Startup check.** The writer verifies only the last record on startup,
  not the whole chain (`verify_chain` checks all of it).
- **Shutdown.** Shutting down with a full queue can raise and leave logging
  half torn down.
- **Production key not enforced.** "Keyed audit chain required in
  production" is documented but not enforced, and `emit_audit` without a
  configured file sink only logs.
- **Email principals.** Audit records redact email-shaped principals, which
  hides who acted.
- **Console format.** The console formatter (`LOG_FORMAT=console`, for local
  development) doesn't escape newlines.
- **`stdout_reserved`.** `configure_logging(stdout_reserved=True)` refuses to
  start when `sys.stdout` *is* `sys.stderr`. Task 1 configures logging before
  it reserves stdout, so it isn't affected.

**Scope**
- Pattern redaction is best effort. It catches structured identifiers, not
  free-text PII such as names or addresses (that needs NER or ML
  classifiers). Call sites must still avoid logging
  raw prompts and tool arguments.
- SSN detection is US-only. Card detection covers PANs, not CVVs or expiry
  dates on their own.
- One writer per audit file. Multiple replicas each need their own file, or a
  central append-only sink.
- Tail truncation of the audit chain needs an external head-hash anchor.
