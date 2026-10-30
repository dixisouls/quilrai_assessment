# Mistakes & Lessons Log

Every bug we introduced, wrong assumption, failed approach, or spec misread.
Format: **what happened → root cause → fix → prevention.**

---

## Environment

### E1 — `uv` binary is the wrong CPU architecture
- **What happened:** `~/.local/bin/uv` fails with `bad CPU type in executable`.
  The `code-review-graph` MCP server (launched via `uvx`) fails for the same reason.
- **Root cause:** an x86_64 build of `uv` installed on an arm64 Mac without Rosetta.
- **Fix:** user reinstalled `uv` (now `uv 0.13.6 aarch64-apple-darwin`).
- **Prevention:** check `file $(which <tool>)` against `uname -m` when a tool won't run.

### E2 — Workspace package installed as an empty editable
- **What happened:** after scaffolding, every test failed with
  `ModuleNotFoundError: quilr_common` although `uv pip list` showed it installed.
- **Root cause:** the first `uv sync` ran while `common/src/quilr_common/` was
  still empty, so the editable build wrote no `.pth` path hook, and uv cached
  that result on later syncs.
- **Fix:** `uv sync --reinstall-package quilr-common`.
- **Prevention:** create the package's `__init__.py` before the first sync; if
  imports fail, check the dist-info `RECORD` for a `_editable_impl_*.pth` entry.

## Common (shared foundations)

### C1 — Invisible bidi control character written into a test file
- **What happened:** a test meant to contain the *escape* for U+202E RIGHT-TO-LEFT OVERRIDE (to check
  that a Unicode bidi override is rejected in request IDs) ended up with the
  raw invisible character. Ruff flagged `PLE2502`.
- **Root cause:** the escape was decoded while the file was written, so the
  source held the literal character. That is the "Trojan Source" pattern.
- **Fix:** rewrote it as a backslash-u escape (`\u202e`).
- **Recurrence:** the same decoding happened again when writing *this entry*
  through a shell heredoc. Tooling decodes the escape before the shell sees it.
- **Prevention:** keep `PLE2502` enabled; name control characters by code point
  in prose; generate them with `chr()` in code; grep the repo for bidi
  characters before committing.

### C2 — Design trap avoided: stdlib `QueueHandler.prepare` drops data
- **What happened (caught at design time, before any code):**
  `logging.handlers.QueueHandler.prepare` formats the message and then sets
  `exc_info=None`. The background listener thread also can't see the caller's
  `contextvars`, so it would lose both exceptions and request IDs.
- **Fix:** a custom `prepare` captures context and the structured exception on
  the calling thread. Tests `test_exceptions_survive_the_queue` and
  `test_logs_flow_through_queue_with_context_and_redaction` lock this in.
- **Prevention:** read the stdlib source before relying on its behaviour.

### C3 — Stdlib logging fallback would leak unredacted PII
- **What happened:** while testing queue backpressure, a failed audit enqueue
  printed `--- Logging error --- ... Message: 'b'` to stderr. That is the
  stdlib's `Handler.handleError`, and it echoes the **raw, unredacted** record
  message and arguments. My first `HashChainFileHandler.handleError` also
  called `super()`, so it leaked the same way.
- **Root cause:** the redaction pipeline only runs inside formatters. Error
  paths that bypass formatters bypass redaction too.
- **Fix:** `log/fallback.py` writes one structured CRITICAL line containing
  only safe metadata (component, exception type, flags). Both handlers use it
  and count losses (`dropped`, `audit_lost`, `failures`). Tests seed PII into
  the failing record and assert it never reaches stderr.
- **Prevention:** when adding redaction to a pipeline, list every exit path
  (errors, fallbacks, `__repr__`, crash dumps), not just the happy path.

### C4 — First audit chain was tamper-evident only against careless edits
- **What happened:** coverage showed the "broken prev_hash link" branch was
  never hit. Writing that test made it clear an attacker would simply
  recompute the hashes, and with plain SHA-256 anyone with write access can
  rewrite the entire chain so it still verifies.
  `test_unkeyed_chain_cannot_stop_a_full_rewrite` now documents this.
- **Root cause:** I tested the attacks that were easy to write (edit one
  field, delete a line) instead of the attacker who knows how the chain works.
- **Fix:** an optional HMAC-SHA256 keyed chain (`LOG_AUDIT_HMAC_KEY`, at least
  32 characters, `SecretStr`). Every record carries `alg`, and the verifier
  *requires* the expected algorithm, which blocks downgrade to plain SHA-256.
  The writer refuses to extend a chain whose tail fails the key. Tail
  truncation is documented as needing an external head-hash anchor.
- **Prevention:** for every integrity control, write at least one test from the
  viewpoint of an attacker who has read the source code.
