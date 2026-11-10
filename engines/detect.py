"""Auto-detect which vendor a config belongs to, for the sanitize UI."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .cisco.detector import is_cisco_config
from .fortigate.detector import is_fortigate_config
from .mikrotik.detector import is_mikrotik_config

VENDORS = ("opnsense", "fortigate", "mikrotik", "cisco")

LABELS = {
    "opnsense": "OPNsense / pfSense (XML)",
    "fortigate": "FortiGate (CLI)",
    "mikrotik": "MikroTik RouterOS (.rsc)",
    "cisco": "Cisco IOS",
    "unknown": "Unknown",
}


def _xml_root_tag(content: bytes) -> str | None:
    """Return the lowercased local root tag for an XML config, else None."""
    head = content[:512]
    if head[:3] == b"\xef\xbb\xbf":
        head = head[3:]
    if not head.lstrip()[:1] == b"<":
        return None
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None
    return root.tag.rsplit("}", 1)[-1].lower()


def detect_vendor(content: bytes) -> str:
    """Best-effort vendor label: opnsense | fortigate | mikrotik | cisco | unknown."""
    tag = _xml_root_tag(content)
    if tag in ("pfsense", "opnsense"):
        return "opnsense"
    if is_fortigate_config(content):
        return "fortigate"
    if is_mikrotik_config(content):
        return "mikrotik"
    if is_cisco_config(content):
        return "cisco"
    return "unknown"
