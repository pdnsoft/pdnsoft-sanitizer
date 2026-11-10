"""Syntax-preserving secret redaction for Cisco IOS configurations."""

from __future__ import annotations

import re
from dataclasses import dataclass

REPLACEMENT = "<REDACTED>"

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)^(?P<pre>\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d+)?\s+)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*username\s+\S+(?:\s+privilege\s+\d+)?\s+(?:password|secret)"
        r"(?:\s+\d+)?\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*snmp-server\s+community\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*standby\s+\d+\s+authentication(?:\s+(?:text|md5\s+key-string(?:\s+\d+)?))?\s+(?:\d+\s+)?)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*vrrp\s+\d+\s+authentication(?:\s+text)?\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*glbp\s+\d+\s+authentication(?:\s+(?:text|md5\s+key-string(?:\s+\d+)?))?\s+(?:\d+\s+)?)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*(?:tacacs-server|radius-server)\s+host\s+.*?\bkey\s+(?:\d+\s+)?)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*(?:tacacs-server|radius-server)\s+key(?:\s+\d+)?\s+)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*key(?:\s+chain\s+\S+)?(?:\s+\d+)?\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*(?:ip\s+ospf\s+authentication-key|ip\s+ospf\s+message-digest-key\s+\d+\s+md5)\s+(?:\d+\s+)?)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*.*\b(?:pre-shared-key|wpa-psk|key-string|auth-key)\s+(?:\d+\s+)?)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*neighbor\s+\S+\s+password(?:\s+\d+)?\s+)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(
        r"(?i)^(?P<pre>\s*crypto\s+isakmp\s+key\s+)"
        r"(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(  # line config: ' password <x>' (line vty/con/aux)
        r"(?i)^(?P<pre>\s*password\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(  # EZVPN client: 'group <n> key <x>'
        r"(?i)^(?P<pre>\s*group\s+\d+\s+key(?:\s+\d+)?\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
    re.compile(  # aaa group / tacacs NAS: 'nas <ip> key <x>'
        r"(?i)^(?P<pre>\s*nas\s+\S+\s+key(?:\s+\d+)?\s+)(?P<val>\S+)(?P<post>.*)$"
    ),
)

_SNMP_USER_AUTH = re.compile(
    r"(?i)(\bsnmp-server\s+user\s+\S+\s+\S+(?:\s+v3)?\s+auth\s+(?:md5|sha)\s+)(\S+)"
)
_SNMP_USER_PRIV = re.compile(
    r"(?i)(\bpriv\s+(?:des|3des|aes(?:\s+\d+)?)\s+)(\S+)"
)
_SNMP_HOST_V12 = re.compile(
    r"(?i)^(\s*snmp-server\s+host\s+\S+\s+version\s+(?:1|2c)\s+)(\S+)(.*)$"
)


@dataclass(frozen=True)
class CiscoRedactionResult:
    content: str
    redacted_values: int


def redact_cisco_config(
    content: str | bytes, *, replacement: str = REPLACEMENT, mapper=None
) -> CiscoRedactionResult:
    """Replace secrets in an IOS config while preserving command structure."""
    text = (
        content.decode("utf-8-sig", errors="replace")
        if isinstance(content, (bytes, bytearray))
        else content
    )
    emit = (lambda v: mapper.token(v, "SECRET")) if mapper is not None else (lambda v: replacement)
    count = 0
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        newline = ""
        body = line
        if body.endswith("\r\n"):
            newline = "\r\n"
            body = body[:-2]
        elif body.endswith("\n"):
            newline = "\n"
            body = body[:-1]
        redacted = body
        # SNMPv3 user lines carry two secrets (auth + priv); redact both.
        if redacted.strip().lower().startswith("snmp-server user "):
            new_redacted, n_auth = _SNMP_USER_AUTH.subn(
                lambda m: f"{m.group(1)}{emit(m.group(2))}", redacted
            )
            new_redacted, n_priv = _SNMP_USER_PRIV.subn(
                lambda m: f"{m.group(1)}{emit(m.group(2))}", new_redacted
            )
            if n_auth or n_priv:
                output.append(new_redacted + newline)
                count += n_auth + n_priv
                continue
        # SNMP v1/v2c host community is a shared secret; v3 uses a username.
        host_match = _SNMP_HOST_V12.match(redacted)
        if host_match:
            output.append(
                f"{host_match.group(1)}{emit(host_match.group(2))}{host_match.group(3)}" + newline
            )
            count += 1
            continue
        for pattern in _PATTERNS:
            match = pattern.match(redacted)
            if not match:
                continue
            # Skip 'no service password-encryption' and similar non-secret commands.
            prefix = match.group("pre").strip().lower()
            if prefix.startswith("no service") or prefix == "service password-encryption":
                continue
            if prefix.startswith("key chain "):
                continue
            redacted = f"{match.group('pre')}{emit(match.group('val'))}{match.group('post')}"
            count += 1
            break
        output.append(redacted + newline)
    return CiscoRedactionResult(content="".join(output), redacted_values=count)
