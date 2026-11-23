"""Have I Been Pwned - breached accounts / domains (API key required)."""
from __future__ import annotations

import time
from urllib.parse import quote

from config.settings import settings
from .base import Finding, Source, terms_of

API = "https://haveibeenpwned.com/api/v3"
SENSITIVE = {"Passwords", "Password hints", "Credit cards", "Bank account numbers",
             "Auth tokens", "Security questions and answers", "Partial credit card data"}


def _severity(data_classes: list[str]) -> str:
    dc = set(data_classes or [])
    if dc & {"Passwords", "Auth tokens", "Credit cards", "Bank account numbers"}:
        return "high"
    if dc & SENSITIVE:
        return "medium"
    return "low"


class HIBPSource(Source):
    name = "hibp"
    label = "Have I Been Pwned"
    description = "Watchlisted e-mails / verified domains found in known breaches"

    def enabled(self) -> bool:
        return bool(settings.HIBP_API_KEY)

    def run(self, terms):
        s = self.session()
        h = {"hibp-api-key": settings.HIBP_API_KEY}
        findings, queries = [], 0
        breach_cache: dict[str, dict] = {}

        def breach(name: str) -> dict:
            if name not in breach_cache:
                breach_cache[name] = self.get_json(s, f"{API}/breach/{quote(name)}", headers=h, ok404=True) or {}
            return breach_cache[name]

        for t in terms_of(terms, "email"):
            queries += 1
            res = self.get_json(s, f"{API}/breachedaccount/{quote(t.value)}", headers=h,
                                params={"truncateResponse": "false"}, ok404=True) or []
            for b in res:
                dcs = b.get("DataClasses", [])
                findings.append(Finding(
                    source=self.name, key=f"hibp:{t.value.lower()}:{b.get('Name')}",
                    title=f"{t.value} appears in breach '{b.get('Title') or b.get('Name')}'",
                    description=(f"Breach date: {b.get('BreachDate')}, added {b.get('AddedDate')}. "
                                 f"Exposed data: {', '.join(dcs)}. Domain: {b.get('Domain') or '-'}."),
                    severity=_severity(dcs), url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
                    matched=t, indicators=[("email", t.value.lower())], published=b.get("AddedDate", "")))
            time.sleep(6.5)  # lowest HIBP tier: 10 requests / minute
        if settings.HIBP_CHECK_DOMAINS:
            for t in terms_of(terms, "domain"):
                queries += 1
                res = self.get_json(s, f"{API}/breacheddomain/{quote(t.value.lstrip('@'))}",
                                    headers=h, ok404=True) or {}
                per_breach: dict[str, list[str]] = {}
                for alias, names in res.items():
                    for n in names:
                        per_breach.setdefault(n, []).append(alias)
                for name, aliases in per_breach.items():
                    b = breach(name)
                    dcs = b.get("DataClasses", [])
                    findings.append(Finding(
                        source=self.name, key=f"hibp-domain:{t.value.lower()}:{name}",
                        title=f"{len(aliases)} account(s) @{t.value} in breach '{b.get('Title') or name}'",
                        description=(f"Accounts: {', '.join(a + '@' + t.value for a in aliases[:25])}"
                                     f"{' …' if len(aliases) > 25 else ''}. Breach date: {b.get('BreachDate', '?')}. "
                                     f"Exposed data: {', '.join(dcs) or '?'}."),
                        severity=_severity(dcs), matched=t,
                        url=f"https://haveibeenpwned.com/PwnedWebsites#{name}"))
                time.sleep(6.5)
        return findings, queries
