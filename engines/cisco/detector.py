"""Content-based detection for Cisco IOS / IOS-XE switch and router configs."""

from __future__ import annotations

import re
from dataclasses import dataclass


_HOSTNAME = re.compile(r"(?m)^hostname\s+\S+")
_VERSION = re.compile(r"(?m)^version\s+\d")
_INTERFACE = re.compile(
    r"(?m)^interface\s+"
    r"(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|FortyGigabitEthernet|"
    r"Ethernet|Vlan|Port-channel|Loopback|Serial|Tunnel|Dialer|Te|Gi|Fa|Po)\S*",
    re.I,
)
_GENERIC_INTERFACE = re.compile(r"(?m)^interface\s+\S+")
_SWITCHPORT = re.compile(r"(?m)^\s*switchport\b")
_LINE_VTY = re.compile(r"(?m)^line\s+vty\b")
_SPANNING_TREE = re.compile(r"(?m)^spanning-tree\b")
_END = re.compile(r"(?m)^end\s*$")
_XML_PREFIXES = ("<pfsense", "<opnsense", "<?xml")
_FORTIGATE_HEADER = re.compile(r"(?m)^#config-version=")
_FORTIGATE_SYSTEM = re.compile(r"(?m)^\s*config\s+system\s+global\s*$")
_ROUTEROS_HEADER = re.compile(r"(?im)^#.*\bby\s+RouterOS\b")
_ROUTEROS_PATH = re.compile(r"(?m)^\s*/(?:ip|interface|system|snmp)\b")
_MODEL = re.compile(
    r"(?im)^(?:!?\s*)?(?:boot system flash bootflash:|boot system)\s+(?P<model>\S+)"
)
_IOS_XE_MODEL = re.compile(r"(?im)^!?\s*Model\s+Number\s*:\s*(?P<model>.+)$")


@dataclass(frozen=True)
class CiscoDetection:
    """Metadata recovered from a Cisco IOS configuration."""

    platform: str = "cisco"
    config_format: str = "ios-config"
    hostname: str | None = None
    version: str | None = None
    model: str | None = None
    device_role: str = "unknown"


def _as_text(content: str | bytes) -> str:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8-sig", errors="replace")
    return content


def is_cisco_config(content: str | bytes) -> bool:
    """Return True when the content looks like a Cisco IOS running/startup config."""
    text = _as_text(content)
    if "\x00" in text or text.lstrip().lower().startswith(_XML_PREFIXES):
        return False
    if _FORTIGATE_HEADER.search(text) or _FORTIGATE_SYSTEM.search(text):
        return False
    if _ROUTEROS_HEADER.search(text) or _ROUTEROS_PATH.search(text):
        return False

    has_identity = bool(_HOSTNAME.search(text) or _VERSION.search(text))
    has_structure = bool(
        _INTERFACE.search(text)
        or _GENERIC_INTERFACE.search(text)
        or _SWITCHPORT.search(text)
        or _LINE_VTY.search(text)
        or _SPANNING_TREE.search(text)
    )
    if has_identity and has_structure:
        return True
    return bool(_INTERFACE.search(text) and _END.search(text) and _SWITCHPORT.search(text))


def detect_cisco(content: str | bytes) -> CiscoDetection | None:
    """Extract IOS header metadata, or None when unrecognized."""
    text = _as_text(content)
    if not is_cisco_config(text):
        return None

    hostname_match = re.search(r"(?m)^hostname\s+(\S+)", text)
    version_match = re.search(r"(?m)^version\s+(\S+)", text)
    model_match = _IOS_XE_MODEL.search(text) or _MODEL.search(text)
    has_switchport = bool(_SWITCHPORT.search(text))
    has_routing = bool(
        re.search(r"(?m)^(?:ip routing|router\s+(?:ospf|eigrp|bgp|rip|isis)\b)", text, re.I)
        or re.search(r"(?m)^interface\s+Vlan\d+", text, re.I)
    )
    if has_switchport and has_routing:
        role = "l3-switch"
    elif has_switchport:
        role = "l2-switch"
    elif has_routing or re.search(r"(?m)^interface\s+(?:Serial|Tunnel|Dialer)\S*", text, re.I):
        role = "router"
    else:
        role = "unknown"

    return CiscoDetection(
        hostname=hostname_match.group(1).strip('"') if hostname_match else None,
        version=version_match.group(1) if version_match else None,
        model=model_match.group("model").strip() if model_match else None,
        device_role=role,
    )
