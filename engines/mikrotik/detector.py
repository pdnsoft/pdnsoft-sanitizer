"""Content-based detection for MikroTik RouterOS `.rsc` exports."""

from __future__ import annotations

import re
from dataclasses import dataclass


_PATH_LINE = re.compile(r"(?m)^\s*/[A-Za-z][\w-]*(?:\s+[\w-]+)*\s*$")
_COMMAND_LINE = re.compile(r"(?m)^\s*(?:add|set|remove)\s")
_ROUTEROS_HEADER = re.compile(r"(?im)^#.*\bby\s+RouterOS\s+(?P<version>[\w.]+)")
_MODEL = re.compile(r"(?im)^#\s*model\s*=\s*(?P<model>.+?)\s*$")
_SERIAL = re.compile(r"(?im)^#\s*serial\s*number\s*=\s*(?P<serial>.+?)\s*$")
_SOFTWARE_ID = re.compile(r"(?im)^#\s*software\s*id\s*=\s*(?P<software_id>.+?)\s*$")
_IDENTITY = re.compile(r'(?is)/system\s+identity\s+set\s+name=(?P<identity>"[^"]*"|\S+)')
_XML_PREFIXES = ("<pfsense", "<opnsense", "<?xml")


@dataclass(frozen=True)
class MikroTikDetection:
    """Metadata recovered from a RouterOS export header."""

    platform: str = "mikrotik"
    config_format: str = "routeros-rsc"
    model: str | None = None
    routeros_version: str | None = None
    serial_number: str | None = None
    software_id: str | None = None
    identity: str | None = None


def _as_text(content: str | bytes) -> str:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8-sig", errors="replace")
    return content


def is_mikrotik_config(content: str | bytes) -> bool:
    """Return True when the content looks like a RouterOS CLI export."""
    text = _as_text(content)
    if "\x00" in text or text.lstrip().lower().startswith(_XML_PREFIXES):
        return False
    if _ROUTEROS_HEADER.search(text):
        return True
    path_lines = len(_PATH_LINE.findall(text))
    command_lines = len(_COMMAND_LINE.findall(text))
    return path_lines >= 1 and command_lines >= 2


def detect_mikrotik(content: str | bytes) -> MikroTikDetection | None:
    """Extract RouterOS header metadata, or None when unrecognized."""
    text = _as_text(content)
    if not is_mikrotik_config(text):
        return None
    header = _ROUTEROS_HEADER.search(text)
    model = _MODEL.search(text)
    serial = _SERIAL.search(text)
    software_id = _SOFTWARE_ID.search(text)
    identity = _IDENTITY.search(text)
    return MikroTikDetection(
        model=model.group("model").strip() if model else None,
        routeros_version=header.group("version") if header else None,
        serial_number=serial.group("serial").strip() if serial else None,
        software_id=software_id.group("software_id").strip() if software_id else None,
        identity=identity.group("identity").strip('"') if identity else None,
    )
