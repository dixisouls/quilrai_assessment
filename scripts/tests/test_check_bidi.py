"""Tests for the Trojan-Source (invisible / bidi control character) scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from check_bidi import DANGEROUS, find_dangerous, main


@pytest.mark.parametrize("codepoint", sorted(DANGEROUS))
def test_each_dangerous_codepoint_is_detected(tmp_path: Path, codepoint: int) -> None:
    f = tmp_path / "x.py"
    f.write_text(f'ok = 1\nname = "id{chr(codepoint)}"\n', encoding="utf-8")
    [(line, col, cp)] = find_dangerous(f)
    assert (line, col, cp) == (2, 11, codepoint)


def test_escaped_sequences_are_fine(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text('name = "id\\u202e"\n', encoding="utf-8")
    assert find_dangerous(f) == []


def test_ordinary_unicode_is_fine(tmp_path: Path) -> None:
    f = tmp_path / "x.md"
    f.write_text("café — naïve … 日本語 🤖\n", encoding="utf-8")
    assert find_dangerous(f) == []


def test_binary_files_are_skipped(tmp_path: Path) -> None:
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00\xff\xfe" + chr(0x202E).encode())
    assert find_dangerous(f) == []


def test_cli_reports_and_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad, good = tmp_path / "bad.py", tmp_path / "good.py"
    bad.write_text(f"x = '{chr(0x2067)}'\n", encoding="utf-8")
    good.write_text("x = 1\n", encoding="utf-8")
    assert main([str(good)]) == 0
    assert main([str(good), str(bad)]) == 1
    out = capsys.readouterr().out
    assert "bad.py:1:6" in out
    assert "U+2067" in out
