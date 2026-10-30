# Backlog: findings deferred to the task they belong to

Independent reviews sometimes find problems outside the step under review.
They aren't fixed out of order. Each one is recorded here, with the task that
should handle it, and taken up when that task starts.

## For Task 3: streaming PII redaction (reuses `quilr_common.redaction`)

From review #1 (`MISTAKES.md`, "Independent review #1"):

- **HIGH:** email and JWT patterns are quadratic on long runs without a
  match (100 KB takes 7.8 s). Anchor the starts and bound the quantifiers;
  add a timing regression test.
- **HIGH:** key-based redaction misses camelCase and prefixed names
  (`accessToken`, `OPENAI_API_KEY`, `db_password`). Use suffix matching that
  still leaves `prompt_tokens` alone.
- **MEDIUM:** pattern gaps: a card number followed by a CVV, URL userinfo,
  `Basic`/`Token` auth, AWS/GitHub/Slack/Google keys, `password=…` pairs.
  "the bearer of bad news" is a false positive.
- **LOW:** truncation bounds string length only; container sizes and key
  lengths are unbounded.

## For the shared logging package (`common/`), to schedule with the user

From review #1:

- **HIGH:** the listener's `StreamHandler` uses the stdlib `handleError`,
  which can print an unredacted record to stderr.
- **MEDIUM:** any logger can inject records into the audit chain by setting an
  `audit` attribute.
- **MEDIUM:** if fsync fails after a write, the chain's in-memory state
  diverges.
- **MEDIUM:** the writer checks only the tail record on startup, not the whole
  chain.
- **MEDIUM:** shutdown with a full queue can raise and leave logging half torn
  down.
- **MEDIUM:** "keyed audit chain required in production" is documented but not
  enforced. `emit_audit` without a configured sink is silent.
- **MEDIUM:** audit records redact email-shaped principals, which erases who
  performed the action.
- **LOW:** the console formatter doesn't escape newlines in messages.

From review #2:

- `log.exception` tracebacks contain the exception text. Check whether the
  formatter redacts secrets inside tracebacks.
- `configure_logging(stdout_reserved=True)` refuses to start when
  `sys.stdout` *is* `sys.stderr`; the identity check is too literal. Task 1
  works around it by configuring logging before reserving stdout.

## For Task 2: MCP security gateway

From review #2:

- Unbounded stdin line length (SDK) and stderr back-pressure. Request body
  size limits and log draining belong at the gateway and deployment layer.
