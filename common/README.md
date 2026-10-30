# quilr-common

The shared base used by every service in this repo. Today it provides
**structured JSON logging, sensitive-data redaction, request context and a
tamper-evident audit trail**. The error envelopes and JSON-RPC models will be
added here as the tasks need them.

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

## Configuration (`LOG_*` environment variables)

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
stream to stdout/stderr and the platform routes it. In Docker Compose a
shipper collects container output into searchable storage. The audit chain
file sits on a dedicated volume, readable only by its owning service.

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

125 tests, 99% branch coverage: unit tests, Hypothesis properties (generated
emails never survive, redaction is idempotent), concurrency (8 threads writing
one chain, 20 interleaved asyncio tasks), attacker-view tamper tests
(full-rewrite forgery, algorithm downgrade, spliced records, wrong key), and a
subprocess test proving stdout stays byte-empty.

## Known limitations

- Pattern redaction is best effort. It catches structured identifiers, not
  free-text PII such as names or addresses (that needs NER or ML classifiers,
  which QuilrAI does with custom intents). Call sites must still avoid logging
  raw prompts and tool arguments.
- SSN detection is US-only. Card detection covers PANs, not CVVs or expiry
  dates on their own.
- One writer per audit file. Multiple replicas each need their own file, or a
  central append-only sink.
- Tail truncation of the audit chain needs an external head-hash anchor.
