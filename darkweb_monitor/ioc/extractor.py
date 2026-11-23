"""Regex-based IOC extraction from text."""
from __future__ import annotations

import re
import hashlib
from typing import List, Dict

# Patterns
_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ip": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE),
    "btc": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "monero": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
}


def extract(text: str) -> List[Dict]:
    """Return list of {ioc_type, value, context}."""
    results: List[Dict] = []
    seen = set()
    if not text:
        return results
    lines = text.splitlines()
    for ioc_type, pat in _PATTERNS.items():
        for m in pat.finditer(text):
            val = m.group(0).strip().rstrip(".,;:)")
            key = (ioc_type, val.lower())
            if key in seen:
                continue
            seen.add(key)
            # context: surrounding ~80 chars
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 60)
            ctx = text[start:end].replace("\n", " ")
            results.append({"ioc_type": ioc_type, "value": val, "context": ctx})
    return results


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()