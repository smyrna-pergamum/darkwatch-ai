"""Onion website change detection: a compact line diff between page versions."""
from __future__ import annotations

import difflib

MAX_LINES = 40


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def diff_summary(old: str, new: str, watch_terms: list[str] | None = None) -> dict:
    """Return added / removed lines (capped), a similarity ratio and whether a
    watched term appears in the added text (the most interesting kind of change)."""
    a, b = _lines(old), _lines(new)
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(a[i1:i2])
        if tag in ("replace", "insert"):
            added.extend(b[j1:j2])
    added_text = "\n".join(added).lower()
    hits = sorted({t for t in (watch_terms or []) if t and len(t) >= 3 and t.lower() in added_text})
    return {
        "similarity": round(sm.ratio(), 3),
        "added_count": len(added), "removed_count": len(removed),
        "added": [x[:300] for x in added[:MAX_LINES]],
        "removed": [x[:300] for x in removed[:MAX_LINES]],
        "watch_terms_added": hits[:20],
        "kind": _kind(a, b, sm.ratio()),
    }


def _kind(a: list[str], b: list[str], ratio: float) -> str:
    if not a:
        return "new"
    if not b:
        return "emptied"
    if ratio < 0.3:
        return "rewritten"
    if ratio < 0.9:
        return "major"
    return "minor"
