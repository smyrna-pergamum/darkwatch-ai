"""HTML parsing helpers."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


def parse_page(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    # remove scripts/styles
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        full = urljoin(base_url, href)
        links.append(full)
    return {"title": title, "text": text, "links": links}


def is_onion(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host.endswith(".onion")
    except Exception:
        return False


def same_domain(url: str, base: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(base).netloc
    except Exception:
        return False