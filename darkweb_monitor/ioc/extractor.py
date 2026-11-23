"""Regex IOC extraction with validation to cut false positives."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Dict, List

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_PATTERNS = {
    "email": re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b"),
    "ip": re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "onion": re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE),
    "url": re.compile(r"\bhttps?://[^\s<>\"'`{}|\\^\[\]]+", re.IGNORECASE),
    "btc": re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr": re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "telegram": re.compile(r"\b(?:t\.me|telegram\.me)/[A-Za-z0-9_]{5,32}\b", re.IGNORECASE),
    "jabber": re.compile(r"\b(?:xmpp|jabber)\s*[:=]\s*([A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE),
    # email:password combos (credential leaks) - the password is never stored
    "credential": re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})[:;|]([^\s:;|]{4,64})(?=\s|$)"),
}

_VERSION_CTX = re.compile(r"(?:v|ver|version|build|release|firmware)\s*$", re.IGNORECASE)
_FAKE_EMAIL_DOMAINS = {"example.com", "example.org", "domain.com", "email.com", "test.com", "sentry.io"}
_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")


def _b58check(addr: str) -> bool:
    n = 0
    for c in addr:
        if c not in _B58:
            return False
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_ok(addr: str) -> bool:
    addr = addr.lower()
    if not addr.startswith("bc1"):
        return False
    data = [_BECH32.find(c) for c in addr[3:]]
    if -1 in data:
        return False
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in [ord(x) >> 5 for x in "bc"] + [0] + [ord(x) & 31 for x in "bc"] + data:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk in (1, 0x2BC830A3)  # bech32 / bech32m


def _valid(ioc_type: str, val: str, text: str, start: int) -> bool:
    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(val)
        except ValueError:
            return False
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local:
            return False
        if _VERSION_CTX.search(text[max(0, start - 12):start]):
            return False
        return True
    if ioc_type == "email":
        dom = val.split("@", 1)[1].lower()
        return dom not in _FAKE_EMAIL_DOMAINS and not dom.endswith(_IMG_EXT)
    if ioc_type == "btc":
        return _bech32_ok(val) if val.lower().startswith("bc1") else _b58check(val)
    if ioc_type in ("md5", "sha1", "sha256"):
        # all-digit or single repeated char strings are rarely hashes
        return not val.isdigit() and len(set(val.lower())) > 4
    return True


def mask_secret(secret: str) -> str:
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


def extract(text: str, max_per_type: int = 500) -> List[Dict]:
    """Return list of {ioc_type, value, context, confidence}."""
    results: List[Dict] = []
    if not text:
        return results
    seen = set()
    hash_spans: list[tuple[int, int]] = []
    for ioc_type, pat in _PATTERNS.items():
        count = 0
        for m in pat.finditer(text):
            if count >= max_per_type:
                break
            if ioc_type == "jabber":
                val = m.group(1)
            elif ioc_type == "credential":
                # store "email:<masked>" + fingerprint so repeats can be correlated
                fp = hashlib.sha256(m.group(2).encode()).hexdigest()[:12]
                val = f"{m.group(1).lower()}:{mask_secret(m.group(2))}#{fp}"
            else:
                val = m.group(0).strip().rstrip(".,;:)]}>'\"")
            if ioc_type in ("md5", "sha1", "sha256"):
                if any(s <= m.start() < e for s, e in hash_spans):
                    continue
            if not _valid(ioc_type, val, text, m.start()):
                continue
            key = (ioc_type, val.lower())
            if key in seen:
                continue
            seen.add(key)
            if ioc_type in ("md5", "sha1", "sha256"):
                hash_spans.append((m.start(), m.end()))
            s, e = max(0, m.start() - 60), min(len(text), m.end() + 60)
            ctx = text[s:e].replace("\n", " ")
            if ioc_type == "credential":
                ctx = ctx.replace(m.group(2), mask_secret(m.group(2)))
            conf = 0.9 if ioc_type in ("btc", "onion", "cve", "credential", "eth", "xmr") else 0.7
            results.append({"ioc_type": ioc_type, "value": val, "context": ctx, "confidence": conf})
            count += 1
    return results


def mask_credentials(text: str) -> str:
    """Mask passwords in email:password combos before content is stored."""
    return _PATTERNS["credential"].sub(lambda m: f"{m.group(1)}:{mask_secret(m.group(2))}", text or "")


def defang(value: str) -> str:
    return (value.replace("http://", "hxxp://").replace("https://", "hxxps://")
            .replace(".onion", "[.]onion").replace("@", "[@]"))


def content_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()
