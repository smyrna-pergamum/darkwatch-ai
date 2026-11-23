"""Watchlist matching: organisation assets / terms vs. page text."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

KINDS = ("keyword", "brand", "domain", "email", "ip", "crypto", "regex")


@dataclass(frozen=True)
class WatchTerm:
    kind: str
    value: str
    severity: str = "medium"
    id: int | None = None


@lru_cache(maxsize=2048)
def _compile(kind: str, value: str):
    v = value.strip()
    if not v:
        return None
    if kind == "regex":
        if len(v) > 300:
            return None
        try:
            return re.compile(v, re.IGNORECASE)
        except re.error:
            return None
    if kind == "domain":
        d = re.escape(v.lower().lstrip("@").lstrip("."))
        # domain itself, subdomains, or e-mail addresses at the domain
        return re.compile(rf"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)*{d}(?![A-Za-z0-9-])", re.IGNORECASE)
    # keyword / brand / email / ip / crypto -> literal with word-ish boundaries
    return re.compile(rf"(?<![\w]){re.escape(v)}(?![\w])", re.IGNORECASE)


def match(text: str, terms: Iterable[WatchTerm], max_hits: int = 50) -> list[dict]:
    hits = []
    if not text:
        return hits
    for t in terms:
        pat = _compile(t.kind, t.value)
        if pat is None:
            continue
        m = pat.search(text)
        if not m:
            continue
        s, e = max(0, m.start() - 80), min(len(text), m.end() + 80)
        hits.append({"id": t.id, "kind": t.kind, "value": t.value, "severity": t.severity,
                     "matched": m.group(0)[:200], "context": text[s:e].replace("\n", " ")})
        if len(hits) >= max_hits:
            break
    return hits


def validate(kind: str, value: str) -> str | None:
    """Return an error message or None."""
    if kind not in KINDS:
        return f"kind must be one of {', '.join(KINDS)}"
    if not value or not value.strip():
        return "value is required"
    if kind in ("keyword", "brand") and len(value.strip()) < 3:
        return "keywords must be at least 3 characters (too many false positives)"
    if kind == "regex" and _compile(kind, value) is None:
        return "invalid regular expression"
    return None
