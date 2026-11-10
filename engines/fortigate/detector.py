"""Content-based FortiGate CLI backup detection."""

import re
from dataclasses import dataclass


_CONFIG_LINE = re.compile(r"(?m)^\s*config\s+(?:system|firewall|router|vpn|log)\b")
_BLOCK_LINE = re.compile(r"(?m)^\s*(?:edit|set|next|end)\b")
_VERSION_HEADER = re.compile(
    r"(?im)^#config-version=(?P<model>[^-\s:]+)-(?P<version>[\d.]+)"
    r"(?:-[^-:\s]+)?-build(?P<build>\d+)"
)


@dataclass(frozen=True)
class FortiGateDetection:
    platform: str = "fortigate"
    config_format: str = "fortios-cli"
    model: str | None = None
    version: str | None = None
    build: str | None = None
    multi_vdom: bool = False


def _as_text(content: str | bytes) -> str:
    if isinstance(content, bytes):
        return content.decode("utf-8-sig", errors="replace")
    return content


def is_fortigate_config(content: str | bytes) -> bool:
    """Return whether content has the structural markers of a FortiOS backup."""
    text = _as_text(content)
    if "\x00" in text or text.lstrip().startswith(("<pfsense", "<opnsense", "<?xml")):
        return False
    config_lines = len(_CONFIG_LINE.findall(text))
    block_lines = len(_BLOCK_LINE.findall(text))
    return config_lines >= 1 and block_lines >= 2


def detect_fortigate(content: str | bytes) -> FortiGateDetection | None:
    """Detect FortiGate content and extract backup-header metadata."""
    text = _as_text(content)
    if not is_fortigate_config(text):
        return None
    header = _VERSION_HEADER.search(text)
    return FortiGateDetection(
        model=header.group("model") if header else None,
        version=header.group("version") if header else None,
        build=header.group("build") if header else None,
        multi_vdom=bool(re.search(r"(?m)^\s*config\s+vdom\s*$", text)),
    )
