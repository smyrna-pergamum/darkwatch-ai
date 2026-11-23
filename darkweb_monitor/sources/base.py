"""Base class and helpers for external intelligence sources.

A source turns the watchlist into queries against a breach / leak / threat
API and returns ``Finding`` objects. The runner (``sources.runner``) stores
them as alerts with provenance (source, timestamp, reference)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests

from config.settings import settings
from .. import __version__
from ..crawler.tor_client import proxies as tor_proxies
from ..watchlist import WatchTerm

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    source: str
    key: str                   # stable id for de-duplication
    title: str
    description: str
    severity: str = "medium"
    url: str = ""              # reference (defanged before notification)
    matched: WatchTerm | None = None
    indicators: list[tuple[str, str]] = field(default_factory=list)  # (type, value)
    discovered_onions: list[str] = field(default_factory=list)
    published: str = ""


class SourceError(RuntimeError):
    pass


class Source:
    name = "base"
    label = "Base"
    description = ""
    needs_key = True

    def enabled(self) -> bool:
        return False

    def run(self, terms: list[WatchTerm]) -> tuple[list[Finding], int]:
        """Return (findings, number_of_queries)."""
        raise NotImplementedError

    # helpers -------------------------------------------------------------
    def session(self, via_tor: bool | None = None) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = f"darkwatch-ai/{__version__} (+defensive monitoring)"
        if via_tor if via_tor is not None else settings.EXTERNAL_API_VIA_TOR:
            s.proxies.update(tor_proxies())
        return s

    def get_json(self, s: requests.Session, url: str, *, headers=None, params=None,
                 method: str = "GET", json_body=None, ok404: bool = False, retries: int = 3):
        for attempt in range(retries):
            r = s.request(method, url, headers=headers, params=params, json=json_body, timeout=40)
            if r.status_code == 404 and ok404:
                return None
            if r.status_code == 429 and attempt < retries - 1:
                wait = float(r.headers.get("Retry-After", 2 + attempt * 3))
                time.sleep(min(wait, 30))
                continue
            if r.status_code >= 400:
                raise SourceError(f"{self.name}: HTTP {r.status_code} {r.text[:200]}")
            return r.json() if r.content else None
        raise SourceError(f"{self.name}: rate limited")


def terms_of(terms: list[WatchTerm], *kinds: str) -> list[WatchTerm]:
    return [t for t in terms if t.kind in kinds]
