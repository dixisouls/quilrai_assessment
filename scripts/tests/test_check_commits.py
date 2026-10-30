"""Tests for the commit-message policy checker."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from check_commits import check_message, main

GOOD = """feat(common): add redaction for observability data

Everything written to logs passes through redact_text first.
"""


def test_valid_message_passes() -> None:
    assert check_message(GOOD) == []


@pytest.mark.parametrize(
    "header",
    [
        "feat(task1): add MCP server",
        "fix(task2): reject batch smuggling",
        "docs: update readme",
        "security(common)!: rotate audit key format",
        "build(docker): pin base image digest",
    ],
)
def test_conventional_headers_pass(header: str) -> None:
    assert check_message(header + "\n") == []


@pytest.mark.parametrize(
    "header",
    [
        "added stuff",
        "Feat(common): capitalised type",
        "feat(Common): capitalised scope",
        "feat(common) missing colon",
        "feat(common):missing space",
        "wip(common): unknown type",
        "feat(common): ",
        "feat(common): ends with period.",
    ],
)
def test_bad_headers_fail(header: str) -> None:
    errors = check_message(header + "\n")
    assert errors
    assert any("header" in e for e in errors)


def test_header_too_long_fails() -> None:
    errors = check_message("feat(common): " + "x" * 60 + "\n")
    assert any("72" in e for e in errors)


def test_body_must_be_separated_by_blank_line() -> None:
    errors = check_message("feat(common): add thing\nbody starts immediately\n")
    assert any("blank line" in e for e in errors)


def test_long_body_line_fails_unless_it_is_a_url() -> None:
    long_line = "word " * 30
    assert check_message(f"feat(common): add thing\n\n{long_line}\n")
    url_line = "See https://example.com/" + "a" * 120
    assert check_message(f"feat(common): add thing\n\n{url_line}\n") == []


@pytest.mark.parametrize(
    "trailer",
    [
        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
        "co-authored-by: claude <someone@example.com>",
        "🤖 Generated with [Claude Code](https://claude.com/claude-code)",
        "Generated with Claude Code",
        "Co-Authored-By: GitHub Copilot <copilot@github.com>",
        "Signed-off-by: ChatGPT <bot@openai.com>",
    ],
)
def test_ai_attribution_is_rejected(trailer: str) -> None:
    errors = check_message(f"{GOOD}\n{trailer}\n")
    assert any("attribution" in e for e in errors)


def test_human_coauthor_is_allowed() -> None:
    assert check_message(f"{GOOD}\nCo-Authored-By: Jane Doe <jane@example.com>\n") == []


@pytest.mark.parametrize(
    "message",
    [
        "Merge pull request #3 from dixisouls/task/1-mcp-server\n\nTask 1\n",
        "Merge branch 'main' into task/2-mcp-gateway\n",
        'Revert "feat(common): add thing"\n\nThis reverts commit abc123.\n',
    ],
)
def test_git_generated_messages_are_allowed(message: str) -> None:
    assert check_message(message) == []


def test_comment_lines_from_editor_are_ignored() -> None:
    msg = "feat(common): add thing\n# Please enter the commit message\n# Lines starting with #\n"
    assert check_message(msg) == []


def test_empty_message_fails() -> None:
    assert check_message("\n\n# only comments\n")


# --- CLI ----------------------------------------------------------------------


def test_cli_file_mode(tmp_path: Path) -> None:
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.write_text(GOOD)
    bad.write_text("nope\n")
    assert main(["--file", str(good)]) == 0
    assert main(["--file", str(bad)]) == 1


@pytest.mark.integration
def test_cli_range_mode_against_real_repo(tmp_path: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.run(  # noqa: S603 - fixed git argv in a temp repo
            ["git", "-C", str(tmp_path), *args],  # noqa: S607 - git from PATH is intended
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "T")
    git("commit", "-q", "--allow-empty", "-m", "chore(repo): initial commit")
    base = git("rev-parse", "HEAD")
    git("commit", "-q", "--allow-empty", "-m", "feat(common): add thing")
    assert main(["--range", f"{base}..HEAD", "--repo", str(tmp_path)]) == 0
    git("commit", "-q", "--allow-empty", "-m", "bad message", "-m", "Co-Authored-By: Claude <x@y>")
    assert main(["--range", f"{base}..HEAD", "--repo", str(tmp_path)]) == 1


# --- Review findings ------------------------------------------------------------


def test_hash_prefixed_header_is_content_in_range_mode() -> None:
    # In --range mode messages come from git log: '#' lines are real content.
    errors = check_message("#42 fix thing\n", strip_comments=False)
    assert errors != ["empty commit message"]
    assert any("header" in e for e in errors)


def test_verbose_commit_scissors_section_is_ignored() -> None:
    msg = (
        "feat(common): add thing\n\n"
        "Body.\n"
        "# ------------------------ >8 ------------------------\n"
        "# Do not modify or remove the line above.\n"
        "diff --git a/x b/x\n" + "+" + "y" * 150 + "\n"
    )
    assert check_message(msg) == []


@pytest.mark.parametrize(
    "header",
    [
        "build(deps): bump the py group across 1 directory with 12 updates",
        "build(deps-dev): bump the py group across 1 directory with 12 updates",
        "ci(deps): bump the actions group across 1 directory with 3 updates",
        "build(deps): bump pydantic-settings from 2.16.2 to 2.17.0",
    ],
)
def test_dependabot_titles_fit_the_policy(header: str) -> None:
    assert check_message(header + "\n") == []
