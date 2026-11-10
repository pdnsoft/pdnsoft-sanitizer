"""Deterministic, reversible token mapping for redacted config values.

A `TokenMapper` turns each distinct redacted value into a stable token
(same value -> same token, across every file in a run) and keeps the reverse
lookup so a sanitized file can be restored.

SECURITY: the mapping holds the *original* secrets in plaintext. It is exactly
as sensitive as the source config. Never ship it alongside sanitized output.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

# Category -> token template. Categories sharing a template share one counter,
# so numbers never collide within a document (e.g. Secret and Cert both [REDACTED:n]).
_FORMAT: dict[str, str] = {
    "SECRET": "[REDACTED:{n}]",
    "CERT": "[REDACTED:{n}]",
    "URLSECRET": "[REDACTED:{n}]",
    "IP": "IP_{n}",
    "DOMAIN": "DOMAIN_{n}",
    "MAC": "MAC_{n}",
    "EMAIL": "EMAIL_{n}",
    "FQDN": "FQDN_{n}",
    "URL": "URL_{n}",
}


class TokenMapper:
    """Deterministic reversible mapping: value <-> token."""

    def __init__(self) -> None:
        self._fwd: dict[tuple[str, str], str] = {}
        self._rev: dict[str, str] = {}
        self._counters: dict[str, int] = defaultdict(int)

    def token(self, value: str, category: str = "SECRET") -> str:
        """Return the stable token for `value`; assign on first sight."""
        if value is None or value == "":
            return value  # nothing to map
        if value.strip() == "":
            return value  # whitespace-only: not a secret, keep the mapping clean
        key = (category, value)
        existing = self._fwd.get(key)
        if existing is not None:
            return existing

        template = _FORMAT.get(category, "[REDACTED:{n}]")
        # Skip forward if the generated token is already taken (defensive).
        while True:
            self._counters[template] += 1
            tok = template.format(n=self._counters[template])
            if tok not in self._rev:
                break
        self._fwd[key] = tok
        self._rev[tok] = value
        return tok

    def restore(self, text: str) -> str:
        """Replace every token in `text` with its original value."""
        # Longest tokens first so [REDACTED:10] isn't clobbered by [REDACTED:1].
        for tok in sorted(self._rev, key=len, reverse=True):
            # URL query values get percent-encoded; restore that form too.
            text = text.replace(quote(tok, safe=""), self._rev[tok])
            text = text.replace(tok, self._rev[tok])
        return text

    # ---------- persistence ----------

    def to_dict(self) -> dict:
        return {
            "entries": [
                {"category": cat, "value": val, "token": tok}
                for (cat, val), tok in self._fwd.items()
            ]
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenMapper":
        m = cls()
        for entry in data.get("entries", []):
            cat, val, tok = entry["category"], entry["value"], entry["token"]
            m._fwd[(cat, val)] = tok
            m._rev[tok] = val
        return m

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load_json(cls, path: str | Path) -> "TokenMapper":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def save_csv(self, path: str | Path) -> None:
        """Human-readable table: category, token, original value."""
        with Path(path).open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["category", "token", "original_value"])
            for (cat, val), tok in self._fwd.items():
                w.writerow([cat, tok, val])

    def __len__(self) -> int:
        return len(self._fwd)
