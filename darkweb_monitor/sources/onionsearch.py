"""Several onion search engines at once (like the OnionSearch tool):
Torch, Haystak, Tor66, Excavator, OnionLand ... - configurable list.

Only reachable through Tor. Every engine is queried separately; one dead
engine never stops the others. Found onions become *proposed* targets."""
from __future__ import annotations

from urllib.parse import quote_plus, urlparse

from bs4 import BeautifulSoup

from config.settings import settings
from .ahmia import onions_in, tor_usable
from .base import Finding, Source, SourceError, terms_of


def engines() -> list[tuple[str, str]]:
    out = []
    for line in str(settings.ONION_SEARCH_ENGINES or "").replace("\\n", "\n").splitlines():
        if "|" in line and "{q}" in line:
            name, url = line.split("|", 1)
            if name.strip() and url.strip().startswith("http"):
                out.append((name.strip(), url.strip()))
    return out


def parse_engine(html: str, own: str) -> dict[str, str]:
    """onion host -> link text (title) for every onion address in the results."""
    soup = BeautifulSoup(html or "", "html.parser")
    out: dict[str, str] = {}
    for a in soup.find_all("a", href=True):
        for h in onions_in(a["href"] + " " + a.get_text(" "), {own}):
            if h not in out or not out[h]:
                out[h] = a.get_text(" ", strip=True)[:200]
    for h in onions_in(soup.get_text(" "), {own}):
        out.setdefault(h, "")
    return out


class OnionSearchSource(Source):
    name = "onionsearch"
    label = "Onion search engines"
    description = "Torch, Haystak, Tor66, Excavator, OnionLand … searched together through Tor"
    needs_key = False
    category = "darkweb"
    kinds = ("brand", "domain", "keyword", "email")
    enable_key = "ONION_SEARCH_ENABLED"
    signup = "https://github.com/megadose/OnionSearch"
    via_tor = True
    sample = ("keyword", "bitcoin")
    fields = [{"key": "ONION_SEARCH_ENGINES", "label": "Engines (name|url with {q}, one per line)", "type": "text",
               "help": "Search engines on the Tor network change often - add or remove lines here."}]

    def search(self, query: str) -> tuple[list[dict], dict]:
        ok, why = tor_usable()
        if not ok:
            raise SourceError(f"onion search needs Tor: {why}. Connect Tor under System.")
        s = self.session(via_tor=True)
        s.headers["User-Agent"] = settings.USER_AGENT
        found: dict[str, dict] = {}
        status: dict[str, str] = {}
        for name, url in engines():
            own = (urlparse(url).hostname or "").removesuffix(".onion")
            try:
                r = s.get(url.replace("{q}", quote_plus(query)), timeout=90)
                if r.status_code >= 400:
                    status[name] = f"HTTP {r.status_code}"
                    continue
                hits = parse_engine(r.text, own)
                status[name] = f"{len(hits)} result(s)"
                for h, title in hits.items():
                    e = found.setdefault(h, {"onion": h + ".onion", "url": f"http://{h}.onion/", "title": title,
                                             "engines": []})
                    e["engines"].append(name)
                    e["title"] = e["title"] or title
            except Exception as e:  # noqa: BLE001
                status[name] = f"error: {type(e).__name__}"
        if status and all(v.startswith(("error", "HTTP")) for v in status.values()):
            raise SourceError("all onion search engines failed: " + ", ".join(f"{k}={v}" for k, v in status.items()))
        ranked = sorted(found.values(), key=lambda x: -len(x["engines"]))
        return ranked[:60], status

    def run(self, terms):
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            results, status = self.search(t.value)
            if not results:
                continue
            hosts = [r["onion"] for r in results]
            findings.append(Finding(
                source=self.name, key=f"onionsearch:{t.value.lower()}:{','.join(sorted(hosts)[:10])}",
                title=f"Onion search: {len(hosts)} site(s) mention '{t.value}'",
                description="Engines: " + ", ".join(f"{k} ({v})" for k, v in status.items()) + "\n" + "\n".join(
                    f"- {r['onion']} [{', '.join(r['engines'])}]{(' — ' + r['title']) if r['title'] else ''}"
                    for r in results[:25]),
                severity="low", matched=t, discovered_onions=[f"http://{h}/" for h in hosts[:20]],
                extra={"results": results, "engines": status}))
        return findings, queries
