"""Exact, non-fuzzy unified patch application for text files."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from .errors import PolicyError


_HUNK_RE = re.compile(
    r"^@@(?:\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?)?\s*@@"
)


@dataclass(frozen=True, slots=True)
class _Hunk:
    old_start: int | None
    old_count: int | None
    new_start: int | None
    new_count: int | None
    lines: tuple[str, ...]


def _content(line: str) -> str:
    if not line or line[0] not in " +-":
        raise PolicyError("PATCH_INVALID", "patch lines must start with space, '+' or '-'")
    return line[1:]


def _parse_hunks(patch: str) -> list[_Hunk]:
    raw_lines = patch.splitlines()
    if not raw_lines:
        raise PolicyError("PATCH_INVALID", "patch is empty")

    begin = any(line.strip() == "*** Begin Patch" for line in raw_lines)
    lines: list[str] = []
    for line in raw_lines:
        if line.startswith("*** Update File:") or line.startswith("*** Begin Patch") or line.startswith("*** End Patch"):
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line == r"\ No newline at end of file":
            continue
        lines.append(line)

    hunks: list[_Hunk] = []
    current_header: tuple[int | None, int | None, int | None, int | None] | None = None
    current_lines: list[str] = []
    for line in lines:
        match = _HUNK_RE.match(line)
        if match:
            if current_header is not None:
                hunks.append(_Hunk(*current_header, tuple(current_lines)))
            if match.group("old_start") is None:
                current_header = (None, None, None, None)
            else:
                current_header = (
                    int(match.group("old_start")),
                    int(match.group("old_count") or "1"),
                    int(match.group("new_start")),
                    int(match.group("new_count") or "1"),
                )
            current_lines = []
            continue
        if current_header is None:
            # A standard diff may contain an informational line, but an actual
            # patch payload must be introduced by a hunk marker.
            if begin and not line.strip():
                continue
            raise PolicyError("PATCH_INVALID", "patch hunk header is missing")
        if line and line[0] in " +-":
            current_lines.append(line)
        elif line.strip():
            raise PolicyError("PATCH_INVALID", "patch contains an invalid hunk line")
    if current_header is not None:
        hunks.append(_Hunk(*current_header, tuple(current_lines)))
    if not hunks:
        raise PolicyError("PATCH_INVALID", "patch contains no hunks")
    return hunks


def _line_text(lines: list[str]) -> list[str]:
    return [line.rstrip("\r\n") for line in lines]


def _find_unique(lines: list[str], expected: list[str]) -> int:
    if not expected:
        return len(lines)
    haystack = _line_text(lines)
    matches = [index for index in range(0, len(haystack) - len(expected) + 1) if haystack[index:index + len(expected)] == expected]
    if not matches:
        raise PolicyError("PATCH_CONTEXT_MISMATCH", "patch context does not match the current file")
    if len(matches) > 1:
        raise PolicyError("PATCH_AMBIGUOUS", "patch context matches multiple locations")
    return matches[0]


def apply_text_patch(original: str, patch: str) -> tuple[str, list[dict[str, int]]]:
    """Apply all hunks exactly and return new text plus changed line ranges.

    No fuzzy matching, offset guessing, or partial hunk application is allowed.
    Hunk coordinates in a standard unified diff are checked against the current
    pre-image; compact ``@@`` hunks use a unique exact context match.
    """

    hunks = _parse_hunks(patch)
    newline = "\r\n" if "\r\n" in original else "\n"
    had_final_newline = original.endswith(("\n", "\r"))
    current = original.splitlines(keepends=True)
    offset = 0

    for hunk in hunks:
        old = [_content(line) for line in hunk.lines if line[0] in " -"]
        new = [_content(line) for line in hunk.lines if line[0] in " +"]
        if hunk.old_start is None:
            index = _find_unique(current, old)
        else:
            # Unified diff uses old_start=0 for an insertion before the first
            # line. For an empty old range, the insertion point is the line
            # boundary itself; non-empty ranges remain one-based.
            index = (hunk.old_start if hunk.old_count == 0 else hunk.old_start - 1) + offset
            if index < 0 or index > len(current) or _line_text(current[index:index + len(old)]) != old:
                raise PolicyError("PATCH_CONTEXT_MISMATCH", "patch hunk coordinates or context do not match the current file")
            if hunk.old_count != len(old) or hunk.new_count != len(new):
                raise PolicyError("PATCH_INVALID", "patch hunk line counts are invalid")
        replacement = [line + newline for line in new]
        current[index:index + len(old)] = replacement
        offset += len(new) - len(old)

    if not current:
        result = ""
    else:
        result = "".join(current)
        if not had_final_newline and result.endswith(newline):
            result = result[:-len(newline)]

    before = _line_text(original.splitlines(keepends=True))
    after = _line_text(result.splitlines(keepends=True))
    changed: list[dict[str, int]] = []
    matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        changed.append(
            {
                "before_start": old_start + 1,
                "before_end": max(old_end, old_start + 1),
                "after_start": new_start + 1,
                "after_end": max(new_end, new_start + 1),
            }
        )
    return result, changed
