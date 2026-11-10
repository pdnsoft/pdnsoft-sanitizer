"""Runnable self-check for the sanitizer engines. No test framework needed.

Run:  python selftest.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engines.cisco.redactor import redact_cisco_config
from engines.detect import detect_vendor
from engines.fortigate.redactor import redact_fortigate_config
from engines.mapping import TokenMapper
from engines.mikrotik.redactor import redact_mikrotik_config
from engines.pfsense_redactor import PfSenseRedactor

FORTIGATE = b"""#config-version=FG60F-7.0.0-build123
config system admin
    edit "admin"
        set password "hunter2forti"
    next
end
"""

MIKROTIK = b"""# model = RB4011
/user
add name=admin password=supersecret3
/ip service
set telnet disabled=yes
"""

CISCO = b"""hostname rtr1
version 15.2
interface GigabitEthernet0/0
 switchport
end
enable secret 5 $1$ab$cdEFsecret
"""

OPNSENSE = b"""<?xml version="1.0"?>
<opnsense>
  <system>
    <user>
      <name>admin</name>
      <password>hunter2xmlsecret</password>
    </user>
  </system>
</opnsense>
"""


def check_detection() -> None:
    assert detect_vendor(FORTIGATE) == "fortigate", detect_vendor(FORTIGATE)
    assert detect_vendor(MIKROTIK) == "mikrotik", detect_vendor(MIKROTIK)
    assert detect_vendor(CISCO) == "cisco", detect_vendor(CISCO)
    assert detect_vendor(OPNSENSE) == "opnsense", detect_vendor(OPNSENSE)


def check_cli_engines() -> None:
    fg = redact_fortigate_config(FORTIGATE)
    assert "hunter2forti" not in fg.content, "fortigate secret leaked"
    assert fg.redacted_values == 1, fg.redacted_values

    mt = redact_mikrotik_config(MIKROTIK)
    assert "supersecret3" not in mt.content, "mikrotik secret leaked"
    assert mt.redacted_values == 1, mt.redacted_values

    cs = redact_cisco_config(CISCO)
    assert "$1$ab$cdEFsecret" not in cs.content, "cisco secret leaked"
    assert cs.redacted_values == 1, cs.redacted_values


def check_xml_engine() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "config.xml"
        out = Path(tmp) / "sanitized-config.xml"
        src.write_bytes(OPNSENSE)
        redactor = PfSenseRedactor()
        assert redactor.redact_config(str(src), str(out)) is True
        text = out.read_text(encoding="utf-8")
        assert "hunter2xmlsecret" not in text, "xml secret leaked"


def check_mapper_off_unchanged() -> None:
    out = redact_fortigate_config(FORTIGATE).content
    assert "[REDACTED:" not in out, "mapper token leaked with mapper disabled"
    assert "<REDACTED>" in out


def check_mapping_cli() -> None:
    m = TokenMapper()
    src = (b'config system admin\n    edit "a"\n'
           b'        set password "dup"\n'
           b'        set passwd "dup"\n'
           b'        set secret "uniq"\n'
           b'    next\nend\n')
    out = redact_fortigate_config(src, mapper=m).content
    assert out.count("[REDACTED:1]") == 2, out  # same value -> same token
    assert "[REDACTED:2]" in out               # distinct value -> new token
    assert "dup" not in out and "uniq" not in out
    restored = m.restore(out)
    assert 'set password "dup"' in restored and 'set secret "uniq"' in restored


def check_mapping_xml() -> None:
    xml = (b'<?xml version="1.0"?>\n<opnsense><system><user>'
           b'<password>hunter2xml</password></user></system>'
           b'<interfaces><wan><ipaddr>203.0.113.9</ipaddr>'
           b'<gateway>203.0.113.9</gateway></wan></interfaces></opnsense>')
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "c.xml"
        out = Path(tmp) / "s.xml"
        src.write_bytes(xml)
        m = TokenMapper()
        PfSenseRedactor(mapper=m).redact_config(str(src), str(out))
        text = out.read_text(encoding="utf-8")
        assert "hunter2xml" not in text
        assert "[REDACTED:1]" in text
        assert text.count("IP_1") == 2, text  # same IP -> same token
        restored = m.restore(text)
        assert "hunter2xml" in restored and "203.0.113.9" in restored


def check_mapping_url_edges() -> None:
    """Overlong URL/email/domain fail-closed branches must stay reversible."""
    long_url = "http://" + "a" * 3000
    long_email = "a" * 320 + "@example.com"
    long_domain = "a" * 260 + ".com"

    m_url = TokenMapper()
    out_url = PfSenseRedactor(mapper=m_url).redact_text(long_url, redact_ips=False, redact_domains=True)
    assert long_url not in out_url
    assert long_url in m_url.restore(out_url), out_url

    m_mail = TokenMapper()
    out_mail = PfSenseRedactor(mapper=m_mail).redact_text(long_email, redact_ips=False, redact_domains=True)
    assert long_email not in out_mail
    assert long_email in m_mail.restore(out_mail), out_mail

    m_dom = TokenMapper()
    out_dom = PfSenseRedactor(mapper=m_dom).redact_text(long_domain, redact_ips=False, redact_domains=True)
    assert long_domain not in out_dom
    assert long_domain in m_dom.restore(out_dom), out_dom

    # mapper off -> historical constant unchanged (byte-identical posture).
    # The overlong branch emits REDACTED@example.invalid, which the later email
    # pass rewrites to user@example.com -- that is the pre-existing upstream output.
    off = PfSenseRedactor().redact_text(long_url, redact_ips=False, redact_domains=True)
    assert off == "http://user@example.com/[REDACTED]", off


def check_cisco_line_secrets() -> None:
    """Bare ' password <x>' (vty/con/aux), EZVPN 'group <n> key <x>',
    and aaa 'nas <ip> key <x>' must be redacted; 'no service password-encryption'
    must stay."""
    src = (b"no service password-encryption\n"
           b"line vty 0 4\n"
           b" password vtypass\n"
           b"crypto ipsec client ezvpn ez\n"
           b" group 2 key ezvpnkey\n"
           b"aaa group server tacacs+\n"
           b" nas 10.0.1.1 key naspass\n")
    out = redact_cisco_config(src).content
    assert "vtypass" not in out, out
    assert "ezvpnkey" not in out, out
    assert "naspass" not in out, out
    assert "no service password-encryption" in out, out


def check_xml_enckey() -> None:
    """SNMPv3 <enckey> is a secret and must be redacted."""
    xml = (b'<?xml version="1.0"?>\n<opnsense><snmpd><user>'
           b'<name>adminsnmp</name><password>authpass</password>'
           b'<enckey>encpass123</enckey>'
           b'</user></snmpd></opnsense>')
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "c.xml"
        out = Path(tmp) / "s.xml"
        src.write_bytes(xml)
        m = TokenMapper()
        PfSenseRedactor(mapper=m).redact_config(str(src), str(out))
        text = out.read_text(encoding="utf-8")
        assert "encpass123" not in text, text
        assert "authpass" not in text
        restored = m.restore(text)
        assert "encpass123" in restored and "authpass" in restored


def check_mapper_skip_whitespace() -> None:
    """Whitespace-only values are not secrets and must not be mapped."""
    m = TokenMapper()
    assert m.token("   ", "SECRET") == "   "
    assert m.token("\n\t", "CERT") == "\n\t"
    assert len(m) == 0, m.to_dict()


def main() -> int:
    checks = (
        check_detection,
        check_cli_engines,
        check_xml_engine,
        check_mapper_off_unchanged,
        check_mapping_cli,
        check_mapping_xml,
        check_mapping_url_edges,
        check_cisco_line_secrets,
        check_xml_enckey,
        check_mapper_skip_whitespace,
    )
    failed = 0
    for name in checks:
        try:
            name()
            print(f"[PASS] {name.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {name.__name__}: {exc}")
    print("ALL PASS" if not failed else f"{failed} CHECK(S) FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
