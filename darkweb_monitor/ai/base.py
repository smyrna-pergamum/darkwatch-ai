"""Shared AI helpers."""
from __future__ import annotations

import json
import re
from typing import Any


class AIError(RuntimeError):
    """Provider unavailable or returned an unusable answer.
    ``code`` is CONTEXT_OVERFLOW when the prompt did not fit the model window."""

    def __init__(self, message: str = "", code: str = "AI_ERROR"):
        super().__init__(message)
        self.code = code


def ai_error(prefix: str, exc_or_msg) -> "AIError":
    from .context import is_context_overflow
    msg = f"{prefix}: {exc_or_msg}"
    return AIError(msg, "CONTEXT_OVERFLOW" if is_context_overflow(msg) else "AI_ERROR")


def parse_json(raw: str) -> Any:
    """Parse a model reply that should be JSON (tolerates code fences / prose)."""
    if raw is None:
        raise AIError("empty reply")
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw)
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        pass
    for pat in (r"\{.*\}", r"\[.*\]"):
        m = re.search(pat, raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:  # noqa: BLE001
                continue
    raise AIError(f"invalid JSON from model: {raw[:200]!r}")


_REDACT = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
    (re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"), "[BTC]"),
    (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "[ETH]"),
    (re.compile(r"(?i)(pass(?:word)?|pwd)\s*[:=]\s*\S+"), r"\1: [REDACTED]"),
]


def redact(text: str) -> str:
    for pat, rep in _REDACT:
        text = pat.sub(rep, text)
    return text
