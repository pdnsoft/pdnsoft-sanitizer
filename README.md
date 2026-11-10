# FW Config Sanitizer

Standalone Tkinter desktop app that strips secrets from firewall configs before
you share them (support, vendor, auditor, AI). Auto-detects the vendor per file.

## Supported vendors

| Vendor | Files | Engine |
|---|---|---|
| OPNsense / pfSense | `*.xml` | pure-Python pfSense redactor (anonymise / aggressive modes) |
| FortiGate | `*.conf`, `*.txt` | `redact_fortigate_config` |
| MikroTik RouterOS | `*.rsc` | `redact_mikrotik_config` |
| Cisco IOS | `*.txt`, `*.conf` | `redact_cisco_config` |

Engines under `engines/` are copied from the firewall-doc-generator so this app
is self-contained. The engines and `selftest.py` need only the Python standard
library; the UI adds three packages: `arabic-reshaper` + `python-bidi` for
Persian RTL rendering (Tk has no bidi/shaping engine — text is pre-shaped and
reordered; native dialogs render RTL on their own), and `pillow` for the chrome
layer — every panel, button, chip and control is an anti-aliased PIL image blitted
onto a `tk.Canvas`, cached and supersampled 2×. Real work (the file table,
entry, log) still uses native ttk widgets.

The UI is Persian and right-to-left: primary content on the right, headings and
labels right-anchored, Treeview columns reversed (file rightmost) with
right-aligned text, and log lines right-justified.

The Persian UI font is the bundled **Vazirmatn** (`fonts/*.ttf`). The app
registers those TTFs process-privately at startup (Windows `AddFontResourceEx`),
so no system font install is needed; it falls back to Segoe UI/Tahoma if the
bundled family is missing. `B-titr.ttf` ships alongside for display use. Tk 8.6
exposes only Regular and Bold, so hierarchy comes from size and colour, not
weight.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python sanitize_ui.py
```

Or double-click `run.bat`.

Self-check (no test framework):

```bash
python selftest.py
```

## Use

1. **Add files…** / **Add folder…** — vendor is auto-detected per file.
2. Set options (XML: anonymise / aggressive / keep-private-ips / URL usernames;
   CLI: replacement token, default `<REDACTED>`).
3. Choose output — beside source (`sanitized-<name>`) or a chosen folder.
4. **Sanitize all**. The log shows per-file redaction counts.

Redaction is **read-only** on the input; output is always a new file. Redacted
output is for analysis only — never restore it to a live device.

## Deterministic reversible mapping

Tick **"Reversible per-value mapping"**. Then every distinct redacted value gets
a stable token, the same value always the same token across all files in the run:

| Kind | Token |
|---|---|
| secrets / certs / URL secrets | `[REDACTED:1]`, `[REDACTED:2]`, … |
| IPs | `IP_1`, `IP_2`, … |
| domains / FQDNs | `DOMAIN_1`, … (`FQDN_1` for bare names) |
| MACs / emails | `MAC_1`, `EMAIL_1`, … |

A mapping file is written next to the output:

- `sanitize-mapping.json` — full machine-readable map (load for restore)
- `sanitize-mapping.csv` — `category, token, original_value` table ("value1 → value2")

**Restore** — click **"Restore from mapping…"**, pick the sanitized file and the
mapping JSON, and originals are written back. URL query tokens are matched in
both raw and percent-encoded form.

⚠️ **The mapping file holds the plaintext originals** — it is exactly as
sensitive as the source config, and anyone with output + map can fully
un-redact. Keep it offline/encrypted; never ship it with the sanitized config.

With mapping off, output matches the upstream engines' constant placeholders, plus
deliberate extra redactions the upstream engines miss:

- OPNsense XML: SNMPv3 `<enckey>`
- Cisco: bare ` password <x>` (line vty/con/aux), EZVPN `group <n> key <x>`,
  aaa `nas <ip> key <x>`

(regression-tested: byte-identical to upstream on configs without those fields).

