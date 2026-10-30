"""Enforce the repo's commit-message policy (see CLAUDE.md, "Repo conventions").

* Conventional Commits header: ``type(scope)!: description``, at most 72 chars,
  lower-case type/scope, no trailing period.
* A blank line between the header and the body; body lines of at most 100 chars
  (URLs exempt).
* No AI-tool attribution (``Co-Authored-By: Claude``, "Generated with ...").
  Work in this repo is submitted under the author's name.
* Git-generated ``Merge ...`` and ``Revert "..."`` messages are accepted.
* In ``--file`` mode (commit-msg hook) ``#`` comment lines and everything below
  the ``git commit -v`` scissors line are ignored, as git itself does. In
  ``--range`` mode messages come from history, so ``#`` lines are content.

Usage:
    python scripts/check_commits.py --file .git/COMMIT_EDITMSG   # commit-msg hook
    python scripts/check_commits.py --range origin/main..HEAD    # CI
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

TYPES: Final = (
    "feat",
    "fix",
    "test",
    "docs",
    "refactor",
    "build",
    "chore",
    "ci",
    "perf",
    "security",
    "style",
    "revert",
)
MAX_HEADER: Final = 72
MAX_BODY_LINE: Final = 100

_HEADER = re.compile(
    rf"^(?:{'|'.join(TYPES)})(?:\([a-z0-9][a-z0-9-]*\))?!?: \S(?:.*\S)?$",
)
_GIT_GENERATED = re.compile(r"^(?:Merge (?:pull request|branch|remote-tracking branch) |Revert \")")
_SCISSORS = "# ------------------------ >8 ------------------------"
_AI_NAMES = r"(?:claude|anthropic|copilot|chatgpt|openai|gemini|cursor|codex)"
_AI_ATTRIBUTION = (
    re.compile(rf"(?im)^\s*(?:co-authored-by|signed-off-by|generated-by):.*{_AI_NAMES}"),
    re.compile(r"(?i)generated (?:with|by) .*(?:claude|copilot|chatgpt|ai\b)"),
    re.compile(r"(?i)noreply@anthropic\.com"),
)


def check_message(message: str, *, strip_comments: bool = True) -> list[str]:
    """Return a list of policy violations (empty means OK).

    ``strip_comments`` mirrors git's ``--cleanup=strip`` for messages still in
    the editor; disable it for messages read back from history.
    """
    lines = message.splitlines()
    if strip_comments:
        if _SCISSORS in lines:
            lines = lines[: lines.index(_SCISSORS)]
        lines = [ln for ln in lines if not ln.startswith("#")]
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines or not lines[0].strip():
        return ["empty commit message"]

    errors: list[str] = []
    header = lines[0]
    text = "\n".join(lines)
    if any(p.search(text) for p in _AI_ATTRIBUTION):
        errors.append("AI-tool attribution is not allowed in commit messages")
    if _GIT_GENERATED.match(header):
        return errors

    if not _HEADER.match(header) or header.endswith("."):
        errors.append(
            f"header must be 'type(scope): description' with type in {', '.join(TYPES)}, "
            f"lower-case scope, no trailing period: {header!r}"
        )
    if len(header) > MAX_HEADER:
        errors.append(f"header is {len(header)} chars; max is {MAX_HEADER}")
    if len(lines) > 1 and lines[1].strip():
        errors.append("separate the header from the body with a blank line")
    for i, line in enumerate(lines[2:], start=3):
        if len(line) > MAX_BODY_LINE and "://" not in line:
            errors.append(f"body line {i} is {len(line)} chars; max is {MAX_BODY_LINE}")
    return errors


def _messages_in_range(rev_range: str, repo: Path) -> list[tuple[str, str]]:
    out = subprocess.run(  # noqa: S603 - argv is fixed apart from the revision range
        ["git", "-C", str(repo), "log", "--format=%H%x00%B%x1e", rev_range],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    commits = []
    for raw in out.split("\x1e"):
        if chunk := raw.strip("\n"):
            sha, _, body = chunk.partition("\x00")
            commits.append((sha, body))
    return commits


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", type=Path, help="commit message file (commit-msg hook)")
    mode.add_argument("--range", dest="rev_range", help="git revision range, e.g. A..B")
    parser.add_argument("--repo", type=Path, default=Path(), help="repository path")
    args = parser.parse_args(argv)

    strip_comments = args.file is not None
    if args.file is not None:
        targets = [("(commit message)", args.file.read_text(encoding="utf-8"))]
    else:
        targets = _messages_in_range(args.rev_range, args.repo)

    failed = False
    for sha, message in targets:
        for error in check_message(message, strip_comments=strip_comments):
            failed = True
            sys.stdout.write(f"{sha[:12]}: {error}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
