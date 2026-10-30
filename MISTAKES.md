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
