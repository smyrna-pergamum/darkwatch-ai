"""Ransomware leak-site victims via the public ransomware.live API.

Monitors ransomware leak sites without crawling them directly: the service
aggregates victim posts of known groups. Matches watch domains / brands."""
from __future__ import annotations

from urllib.parse import quote

from config.settings import settings
from .base import Finding, Source, terms_of


def _field(v: dict, *names: str) -> str:
    for n in names:
        if v.get(n):
            return str(v[n])
    return ""


class RansomwareLiveSource(Source):
    name = "ransomware"
    label = "Ransomware leak sites"
    description = "Victim posts on ransomware leak sites (ransomware.live)"
    needs_key = False

    def enabled(self) -> bool:
        return settings.RANSOMWARE_LIVE_ENABLED

    def run(self, terms):
        s = self.session()
        base = settings.RANSOMWARE_LIVE_URL.rstrip("/")
        headers = {"X-API-KEY": settings.RANSOMWARE_LIVE_API_KEY} if settings.RANSOMWARE_LIVE_API_KEY else {}
        findings, queries = [], 0
        for t in terms_of(terms, "domain", "brand"):
            q = t.value.lstrip("@")
            if t.kind == "domain":
                q = q.split(".")[0] if len(q.split(".")[0]) >= 4 else q
            queries += 1
            res = self.get_json(s, f"{base}/searchvictims/{quote(q)}", headers=headers, ok404=True) or []
            if isinstance(res, dict):
                res = res.get("victims") or res.get("data") or []
            needle = t.value.lower().lstrip("@")
            for v in res:
                name = _field(v, "victim", "post_title", "name")
                domain = _field(v, "domain", "website")
                blob = f"{name} {domain} {_field(v, 'description')}".lower()
                if needle not in blob and q.lower() not in blob:
                    continue
                group = _field(v, "group", "group_name")
                findings.append(Finding(
                    source=self.name, key=f"ransomware:{group}:{name.lower()}",
                    title=f"Ransomware group '{group}' lists victim '{name}'",
                    description=(f"Matched watch term '{t.value}'. Victim domain: {domain or '-'}; "
                                 f"country: {_field(v, 'country') or '-'}; discovered: "
                                 f"{_field(v, 'discovered', 'attackdate', 'published') or '?'}."),
                    severity="critical", matched=t,
                    url=_field(v, "url", "post_url", "permalink"),
                    published=_field(v, "discovered", "published")))
        return findings, queries
