"""Intelligence X - leaks, pastes and dark-web collections (API key required)."""
from __future__ import annotations

import time

from config.settings import settings
from .base import Finding, Source, SourceError, terms_of

BUCKET_SEVERITY = {"leaks.private": "high", "leaks.public": "high", "darknet.tor": "high",
                   "darknet.i2p": "high", "pastes": "medium", "dumpster": "low"}


class IntelXSource(Source):
    name = "intelx"
    label = "Intelligence X"
    description = "Search leak, paste and darknet collections for watch terms"

    def enabled(self) -> bool:
        return bool(settings.INTELX_API_KEY)

    def search(self, s, term: str) -> list[dict]:
        base = settings.INTELX_BASE_URL.rstrip("/")
        h = {"x-key": settings.INTELX_API_KEY}
        start = self.get_json(s, f"{base}/intelligent/search", method="POST", headers=h,
                              json_body={"term": term, "maxresults": settings.INTELX_MAX_RESULTS,
                                         "media": 0, "sort": 2, "terminate": []})
        sid = (start or {}).get("id")
        if not sid:
            raise SourceError("intelx: no search id")
        records: list[dict] = []
        for _ in range(10):
            res = self.get_json(s, f"{base}/intelligent/search/result", headers=h,
                                params={"id": sid, "limit": settings.INTELX_MAX_RESULTS}) or {}
            records += res.get("records") or []
            if res.get("status") in (1, 2) or len(records) >= settings.INTELX_MAX_RESULTS:
                break
            time.sleep(2)
        try:
            self.get_json(s, f"{base}/intelligent/search/terminate", headers=h, params={"id": sid})
        except Exception:  # noqa: BLE001
            pass
        return records

    def run(self, terms):
        s = self.session()
        findings, queries = [], 0
        for t in terms_of(terms, "domain", "email", "brand"):
            queries += 1
            for r in self.search(s, t.value):
                bucket = r.get("bucket", "")
                sev = BUCKET_SEVERITY.get(bucket, "medium")
                findings.append(Finding(
                    source=self.name, key=f"intelx:{r.get('systemid')}:{t.value.lower()}",
                    title=f"'{t.value}' found in {r.get('bucketh') or bucket}: {r.get('name') or r.get('systemid')}",
                    description=(f"Record date: {r.get('date', '?')}, bucket: {bucket}, "
                                 f"size: {r.get('size', '?')} bytes. Open in Intelligence X to review."),
                    severity=sev if t.severity != "critical" else "critical", matched=t,
                    url=f"https://intelx.io/?did={r.get('systemid')}", published=r.get("date", "")))
            time.sleep(1)
        return findings, queries
