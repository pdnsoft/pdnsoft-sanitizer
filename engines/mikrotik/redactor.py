"""Syntax-preserving secret redaction for MikroTik RouterOS configurations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .lines import _logical_lines

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "shared-secret",
        "pre-shared-key",
        "wpa-pre-shared-key",
        "wpa2-pre-shared-key",
        "wireless-psk",
        "wireless-enc-key",
        "key",
        "private-key",
        "psk",
        "trap-community",
        "auth-password",
        "encryption-password",
    }
)

_VALUE = r'"(?:[^"\\]|\\.)*"|\S+'
_KEYS_ALT = "|".join(sorted((re.escape(key) for key in SENSITIVE_KEYS), key=len, reverse=True))
_SECRET = re.compile(rf'(?<![\w-])(?P<key>(?:{_KEYS_ALT}))=(?P<val>{_VALUE})')
_NAME = re.compile(rf'(?<![\w-])(?P<key>name)=(?P<val>{_VALUE})')


@dataclass(frozen=True)
class MikroTikRedactionResult:
    content: str
    redacted_values: int


def redact_mikrotik_config(
    content: str | bytes, *, replacement: str = "<REDACTED>", mapper=None
) -> MikroTikRedactionResult:
    """Replace sensitive values in a RouterOS export while preserving syntax."""
    text = (
        content.decode("utf-8-sig", errors="replace")
        if isinstance(content, (bytes, bytearray))
        else content
    )
    count = 0
    path = ""
    output: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        if mapper is not None:
            raw = match.group("val")
            val = raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] == '"' else raw
            return f'{match.group("key")}={mapper.token(val, "SECRET")}'
        return f'{match.group("key")}={replacement}'

    for line in _logical_lines(text):
        stripped = line.strip()
        if stripped.startswith("/") and "=" not in stripped:
            path = " ".join(stripped[1:].split())
            output.append(line)
            continue
        redacted = _SECRET.sub(_replace, line)
        if path == "snmp community":
            redacted = _NAME.sub(_replace, redacted)
        output.append(redacted)

    return MikroTikRedactionResult(content="\n".join(output) + "\n", redacted_values=count)
