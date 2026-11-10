"""RouterOS logical-line rejoin, extracted from the analyzer's parser.

Only the pieces `redactor.py` needs, so this package stays dependency-free
(no pydantic, no models). Source of truth: app/services/mikrotik/parser.py.
"""

from __future__ import annotations

MAX_LOGICAL_LINES = 500_000


class MikroTikParseError(ValueError):
    """Raised when a MikroTik configuration cannot be parsed safely."""


def _trailing_backslashes(text: str) -> int:
    count = 0
    for char in reversed(text):
        if char == "\\":
            count += 1
        else:
            break
    return count


def _logical_lines(text: str) -> list[str]:
    # RouterOS wraps long lines with a trailing "\" and indents the continuation;
    # that indentation is cosmetic and is stripped on rejoin, even inside quoted
    # strings (e.g. hex-escaped names split mid-sequence must rejoin contiguously).
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = []
    buffer = ""
    for physical in text.split("\n"):
        segment = physical.lstrip() if buffer else physical
        if _trailing_backslashes(segment) % 2 == 1:
            buffer += segment[:-1]
            continue
        buffer += segment
        lines.append(buffer)
        buffer = ""
        if len(lines) > MAX_LOGICAL_LINES:
            raise MikroTikParseError("MikroTik configuration exceeds the parser line limit.")
    if buffer:
        lines.append(buffer)
    return lines
