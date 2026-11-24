"""HTML parsing, URL normalisation, scope and safety helpers."""
from __future__ import annotations

import re
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from config.settings import settings

_SKIP_EXT = re.compile(
    r"\.(?:jpe?g|png|gif|webp|bmp|ico|svg|mp4|webm|avi|mov|mkv|mp3|wav|ogg|zip|rar|7z|tar|gz|"
    r"exe|msi|apk|dmg|iso|pdf|docx?|xlsx?|pptx?|css|js|woff2?|ttf)$",
    re.IGNORECASE,
)
_ONION_V3 = re.compile(r"^[a-z2-7]{56}\.onion$")


def normalize_url(url: str) -> str:
    url, _ = urldefrag(url.strip())
    p = urlparse(url)
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    netloc = host + (f":{p.port}" if p.port and not (
        (scheme == "http" and p.port == 80) or (scheme == "https" and p.port == 443)) else "")
    path = p.path or "/"
    return urlunparse((scheme, netloc, path, "", p.query, ""))


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_onion(url: str) -> bool:
    return host_of(url).endswith(".onion")


def is_valid_onion_v3(host: str) -> bool:
    return bool(_ONION_V3.match(host.lower()))


def onion_checksum_ok(host: str) -> bool:
    """Full v3 check (version byte + SHA3 checksum): filters random 56-char
    strings that only look like onion addresses."""
    import base64
    import hashlib
    h = host.lower().removesuffix(".onion").split(".")[-1]
    if len(h) != 56:
        return False
    try:
        raw = base64.b32decode(h.upper())
    except (ValueError, TypeError):
        return False
    pub, chk, ver = raw[:32], raw[32:34], raw[34]
    return ver == 3 and hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2] == chk


def same_host(url: str, base: str) -> bool:
    return host_of(url) == host_of(base)


def in_scope(url: str, start_url: str, scope: str | None = None) -> bool:
    """Decide whether a discovered link may be followed."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    if _SKIP_EXT.search(p.path or ""):
        return False
    scope = (scope or settings.CRAWL_SCOPE or "same_site").lower()
    host = host_of(url)
    if same_host(url, start_url):
        return True
    if scope == "allowed":
        return any(host == a or host.endswith("." + a) or host.endswith(a)
                   for a in settings.list_of("ALLOWED_DOMAINS"))
    if scope == "any_onion":
        allowed = settings.list_of("ALLOWED_DOMAINS")
        if allowed and not any(host.endswith(a) for a in allowed):
            return False
        return host.endswith(".onion")
    return False


def parse_page(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.get_text(strip=True)[:500] if soup.title else ""
    meta_desc = ""
    m = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    if m and m.get("content"):
        meta_desc = m["content"][:500]
    for tag in soup(["script", "style", "noscript", "template", "svg", "title"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    links: list[dict] = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        try:
            full = normalize_url(urljoin(base_url, href))
        except ValueError:
            continue
        if full in seen:
            continue
        seen.add(full)
        anchor = " ".join(a.get_text(" ", strip=True).split())[:160]
        links.append({"url": full, "text": anchor})
    return {"title": title, "text": text, "links": links, "meta_description": meta_desc}


def safety_violation(text: str) -> str | None:
    """Return the matched term if the page must be discarded (abuse content)."""
    low = (text or "").lower()
    for term in settings.list_of("SAFETY_BLOCK_TERMS"):
        if term.lower() in low:
            return term
    return None
