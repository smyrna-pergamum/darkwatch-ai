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
    extra: dict = field(default_factory=dict)  # structured details (shown for ad-hoc searches)


class SourceError(RuntimeError):
    pass


class Source:
    name = "base"
    label = "Base"
    description = ""
    needs_key = True
    category = "breach"            # breach | leak | darkweb | infostealer | exposure | phishing | custom
    kinds: tuple[str, ...] = ()    # watch-term kinds this source can query
    enable_key = ""                # boolean setting that switches a key-less source on/off
    fields: list[dict] = []        # configurable settings shown in the dashboard
    signup = ""                    # where to get an API key / documentation
    via_tor = False                # the source talks to .onion services
    sample = ("domain", "example.com")  # term used by "Test"

    def enabled(self) -> bool:
        if self.enable_key:
            return bool(getattr(settings, self.enable_key, False))
        from config.intel_store import FIELDS
        keys = [f["key"] for f in self.fields if FIELDS.get(f["key"])]
        return bool(keys) and bool(getattr(settings, keys[0], ""))

    def info(self) -> dict:
        from config.intel_store import FIELDS, public_value
        return {"name": self.name, "label": self.label, "description": self.description,
                "needs_key": self.needs_key, "category": self.category, "kinds": list(self.kinds),
                "enable_key": self.enable_key, "signup": self.signup, "via_tor": self.via_tor,
                "custom": False,
                "fields": [{**f, "secret": bool(FIELDS.get(f["key"])), "value": public_value(f["key"])}
                           for f in self.fields]}

    def test(self) -> dict:
        """Cheap live check with a harmless sample term."""
        kind, value = self.sample
        findings, queries = self.run([WatchTerm(kind, value, "low", None)])
        return {"ok": True, "queries": queries, "findings": len(findings),
                "sample": [f.title for f in findings[:3]]}

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
