"""Ahmia onion search (through Tor): finds hidden services mentioning watch
terms. Results become *proposed* add_target tasks - never crawled
automatically."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from config.settings import settings
from ..crawler.parsers import is_valid_onion_v3
from ..crawler.tor_client import ensure_tor
from .base import Finding, Source, terms_of

_ONION = re.compile(r"\b([a-z2-7]{56})\.onion\b")


class AhmiaSource(Source):
    name = "ahmia"
    label = "Ahmia onion search"
    description = "Discover onion sites that mention watch terms (suggests new targets)"
    needs_key = False

    def enabled(self) -> bool:
        return settings.AHMIA_ENABLED

    def run(self, terms):
        ensure_tor()
        s = self.session(via_tor=True)
        base = settings.AHMIA_URL.rstrip("/")
        own = base.split("//")[-1].split(".onion")[0]
        findings, queries = [], 0
        # Ahmia's search form carries a rotating hidden anti-bot field
        home = s.get(base + "/", timeout=60)
        soup = BeautifulSoup(home.text, "html.parser")
        hidden = {i.get("name"): i.get("value", "") for i in soup.select("form input[type=hidden]") if i.get("name")}
        for t in terms_of(terms, "brand", "domain", "keyword"):
            queries += 1
            r = s.get(base + "/search/", params={"q": t.value, **hidden}, timeout=90)
            hosts = sorted({h for h in _ONION.findall(r.text) if h != own and is_valid_onion_v3(h + ".onion")})
            if not hosts:
                continue
            findings.append(Finding(
                source=self.name, key=f"ahmia:{t.value.lower()}:{','.join(hosts[:10])}",
                title=f"Ahmia: {len(hosts)} onion site(s) mention '{t.value}'",
                description="Onion services returned by Ahmia search:\n" + "\n".join(f"- {h}.onion" for h in hosts[:20]),
                severity="low", matched=t, discovered_onions=[f"http://{h}.onion/" for h in hosts[:20]]))
        return findings, queries
