"""Fail if any text file contains invisible bidi / zero-width control characters.

These enable "Trojan Source" attacks (CVE-2021-42574), where code renders
differently from how it executes, e.g. hiding a security check inside what
looks like a string. They also slipped into this repo once by accident
(see MISTAKES.md C1). Write them as escapes such as ``\\u202e`` instead.

Usage: ``python scripts/check_bidi.py [FILE ...]`` (default: all git-tracked files).
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

DANGEROUS: Final = frozenset(
    {
        *range(0x202A, 0x202F),  # LRE, RLE, PDF, LRO, RLO
        *range(0x2066, 0x206A),  # LRI, RLI, FSI, PDI
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x061C,  # ARABIC LETTER MARK
        0x200B,  # ZERO WIDTH SPACE
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (allowed only as a leading BOM)
    }
)


def find_dangerous(path: Path) -> list[tuple[int, int, int]]:
    """Return (line, column, codepoint) for each hit; 1-based. Binary files are skipped."""
    data = path.read_bytes()
    if b"\x00" in data:
        return []
    text = data.decode("utf-8", errors="replace")
    hits: list[tuple[int, int, int]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line, start=1):
            cp = ord(ch)
            if cp in DANGEROUS and not (cp == 0xFEFF and lineno == 1 and col == 1):  # noqa: PLR2004
                hits.append((lineno, col, cp))
    return hits


def _tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607 - git from PATH is intended
        check=True,
        capture_output=True,
    ).stdout
    return [Path(p) for p in out.decode().split("\0") if p]


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    files = [Path(a) for a in args] if args else _tracked_files()
    failed = False
    for path in files:
        if not path.is_file():
            continue
        for line, col, cp in find_dangerous(path):
            failed = True
            sys.stdout.write(f"{path}:{line}:{col}: invisible control character U+{cp:04X}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
