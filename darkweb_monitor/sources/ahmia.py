"""Ahmia onion search: finds hidden services that mention watch terms.

Results become *proposed* add_target tasks - never crawled automatically.

Why it used to fail: the source was off by default and could only be switched
on in ``.env``; without Tor it crashed instead of explaining; Ahmia's search
form carries a rotating hidden anti-bot field that has to be read from the
same session before every search; and result links are wrapped in
``/search/redirect?redirect_url=...``. All handled here, with an optional
clearnet fallback (ahmia.fi) when Tor is not connected."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse

from bs4 import BeautifulSoup

from config.settings import settings
from ..crawler.parsers import onion_checksum_ok
from .base import Finding, Source, SourceError, terms_of

_ONION = re.compile(r"\b([a-z2-7]{56})\.onion\b", re.IGNORECASE)


def onions_in(text: str, exclude: set[str] = frozenset()) -> list[str]:
    out = []
    for h in _ONION.findall(unquote(text or "")):
        h = h.lower()
        if h not in exclude and h not in out and onion_checksum_ok(h):
            out.append(h)
    return out


def tor_usable() -> tuple[bool, str]:
    if not settings.TOR_ENABLED:
        return False, "Tor is disabled (TOR_ENABLED=false)"
    from ..crawler.tor_client import tor_status
    st = tor_status()
    if not st.get("is_tor"):
        st = tor_status(force=True)
    return bool(st.get("is_tor")), (st.get("error") or "Tor not verified")


def parse_results(html: str, own: str = "") -> list[dict]:
    """Ahmia result list -> [{onion, url, title, snippet}] (onion-checked)."""
    soup = BeautifulSoup(html or "", "html.parser")
    out: dict[str, dict] = {}
    for li in soup.select("li.result"):
        a = li.find("a", href=True)
        href = a["href"] if a else ""
        q = parse_qs(urlparse(href).query)
        target = (q.get("redirect_url") or [href])[0]
        cite = li.find("cite")
        hosts = onions_in(target + " " + (cite.get_text(" ") if cite else ""), {own})
        if not hosts:
            continue
        p = li.find("p")
        out.setdefault(hosts[0], {"onion": hosts[0] + ".onion", "url": target if ".onion" in target else f"http://{hosts[0]}.onion/",
                                  "title": (a.get_text(" ", strip=True) if a else "")[:200],
                                  "snippet": (p.get_text(" ", strip=True) if p else "")[:400]})
    if not out:  # layout changed: fall back to any onion address on the page
        for h in onions_in(html, {own}):
            out[h] = {"onion": h + ".onion", "url": f"http://{h}.onion/", "title": "", "snippet": ""}
    return list(out.values())


class AhmiaSource(Source):
    name = "ahmia"
    label = "Ahmia onion search"
    description = "Discover onion sites that mention watch terms (suggests new targets)"
    needs_key = False
    category = "darkweb"
    kinds = ("brand", "domain", "keyword", "email")
    enable_key = "AHMIA_ENABLED"
    signup = "https://ahmia.fi/about/"
    via_tor = True
    sample = ("keyword", "bitcoin")
    fields = [{"key": "AHMIA_MODE", "label": "Connection", "type": "select", "options": ["auto", "tor", "clearnet"],
               "help": "auto = through Tor, ahmia.fi (clearnet) if Tor is not connected. clearnet reveals the search "
                       "term and your IP to ahmia.fi."},
              {"key": "AHMIA_URL", "label": "Onion address"},
              {"key": "AHMIA_CLEARNET_URL", "label": "Clearnet mirror"},
              {"key": "AHMIA_MAX_RESULTS", "label": "Max results per term", "type": "int"}]

    def endpoints(self) -> list[tuple[str, bool]]:
        mode = (settings.AHMIA_MODE or "auto").lower()
        if mode == "clearnet":
            return [(settings.AHMIA_CLEARNET_URL, False)]
        ok, why = tor_usable()
        if mode == "tor":
            if not ok:
                raise SourceError(f"ahmia: Tor is required (AHMIA_MODE=tor) but not connected: {why}. "
                                  "Connect Tor under System, or set the connection to 'auto'.")
            return [(settings.AHMIA_URL, True)]
        return ([(settings.AHMIA_URL, True)] if ok else []) + [(settings.AHMIA_CLEARNET_URL, False)]

    def _search_once(self, base: str, via_tor: bool, query: str) -> list[dict]:
        s = self.session(via_tor=via_tor)
        s.headers["User-Agent"] = settings.USER_AGENT
        timeout = 90 if via_tor else 30
        own = (urlparse(base).hostname or "").removesuffix(".onion")
        for _attempt in range(2):
            home = s.get(base.rstrip("/") + "/", timeout=timeout)
            soup = BeautifulSoup(home.text, "html.parser")
            form = soup.select_one("form#searchForm") or soup.find("form")
            hidden = {i.get("name"): i.get("value", "") for i in (form or soup).select("input[type=hidden]")
                      if i.get("name")}
            r = s.get(base.rstrip("/") + "/search/", params={"q": query, **hidden}, timeout=timeout,
                      headers={"Referer": base.rstrip("/") + "/"})
            if r.status_code >= 400:
                raise SourceError(f"ahmia: HTTP {r.status_code}")
            results = parse_results(r.text, own)
            no_hits = "no results" in r.text.lower() or "sorry, but ahmia couldn't find" in r.text.lower()
            if results or no_hits or "result" in r.text:
                return results
            # the page came back without a result list: anti-bot token rotated - retry once
        return []

    def search(self, query: str) -> tuple[list[dict], str]:
        errors = []
        for base, via_tor in self.endpoints():
            try:
                return self._search_once(base, via_tor, query)[: settings.AHMIA_MAX_RESULTS], (
                    "tor" if via_tor else "clearnet")
            except SourceError as e:
                errors.append(str(e))
            except Exception as e:  # noqa: BLE001  (connection errors etc.)
                errors.append(f"{'tor' if via_tor else 'clearnet'}: {type(e).__name__}: {str(e)[:200]}")
        raise SourceError("ahmia unreachable - " + " | ".join(errors))

    def run(self, terms):
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            results, via = self.search(t.value)
            if not results:
                continue
            hosts = [r["onion"] for r in results]
            lines = [f"- {r['onion']}{(' — ' + r['title']) if r['title'] else ''}" for r in results[:20]]
            findings.append(Finding(
                source=self.name, key=f"ahmia:{t.value.lower()}:{','.join(sorted(hosts)[:10])}",
                title=f"Ahmia: {len(hosts)} onion site(s) mention '{t.value}'",
                description=f"Onion services returned by Ahmia ({via}):\n" + "\n".join(lines),
                severity="low", matched=t, discovered_onions=[f"http://{h}/" for h in hosts[:20]],
                extra={"results": results, "via": via}))
        return findings, queries
