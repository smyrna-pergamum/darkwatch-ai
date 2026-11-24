"""More intelligence sources, modelled on what commercial and open-source
dark-web / digital-risk monitors combine (Flare, SpiderFoot, Hudson Rock,
DeHashed, LeakCheck, LeakIX, urlscan, Shodan, crt.sh, psbdmp).

Every source only receives the watch terms you configured. Passwords returned
by breach APIs are never stored - only the fact that a password was exposed."""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from urllib.parse import quote

from config.settings import settings
from ..storage.db import session_scope
from ..storage.models import WatchItem
from .base import Finding, Source, SourceError, terms_of


def _label(domain: str) -> str:
    d = domain.lower().lstrip("@").lstrip(".")
    parts = d.split(".")
    return parts[-2] if len(parts) >= 2 else d


def _own_domains() -> set[str]:
    with session_scope() as s:
        return {w.value.lower().lstrip("@").lstrip(".") for w in s.query(WatchItem).filter_by(kind="domain")}


def _is_own(host: str, own: set[str]) -> bool:
    h = host.lower().strip(".").lstrip("*.")
    return any(h == d or h.endswith("." + d) for d in own)


# ------------------------------------------------------------------ infostealers
class HudsonRockSource(Source):
    name = "hudsonrock"
    label = "Hudson Rock (infostealers)"
    description = "Computers infected by infostealer malware with logins for your domains / e-mails (free API)"
    needs_key = False
    category = "infostealer"
    kinds = ("domain", "email")
    enable_key = "HUDSONROCK_ENABLED"
    signup = "https://www.hudsonrock.com/free-tools"
    fields = [{"key": "HUDSONROCK_URL", "label": "API URL"}]

    def run(self, terms):
        s = self.session()
        base = settings.HUDSONROCK_URL.rstrip("/")
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            if t.kind == "domain":
                d = t.value.lower().lstrip("@")
                r = self.get_json(s, f"{base}/search-by-domain", params={"domain": d}, ok404=True) or {}
                emp, users = int(r.get("employees") or 0), int(r.get("users") or 0)
                third = int(r.get("third_parties") or 0)
                if emp or users or third:
                    findings.append(Finding(
                        source=self.name, key=f"hudsonrock:{d}:{emp}:{users}:{third}",
                        title=f"Infostealer infections with {d} credentials: {emp} employee(s), {users} user(s)",
                        description=(f"Hudson Rock reports {emp} compromised employee computer(s), {users} user(s) and "
                                     f"{third} third-party login(s) for {d}. Last employee compromise: "
                                     f"{r.get('last_employee_compromised') or '?'}; last user: "
                                     f"{r.get('last_user_compromised') or '?'}. Reset affected credentials and "
                                     "check SSO / VPN logs."),
                        severity="critical" if emp else "high", matched=t,
                        url=f"https://www.hudsonrock.com/search?domain={quote(d)}",
                        extra={k: r.get(k) for k in ("total", "employees", "users", "third_parties",
                                                     "last_employee_compromised", "last_user_compromised")}))
            else:
                r = self.get_json(s, f"{base}/search-by-email", params={"email": t.value}, ok404=True) or {}
                for st in (r.get("stealers") or [])[:20]:
                    when = st.get("date_compromised") or "?"
                    findings.append(Finding(
                        source=self.name, key=f"hudsonrock:{t.value.lower()}:{when}:{st.get('computer_name')}",
                        title=f"{t.value} found in an infostealer log (compromised {when[:10]})",
                        description=(f"Computer: {st.get('computer_name') or '?'}, OS: {st.get('operating_system') or '?'}, "
                                     f"malware path: {st.get('malware_path') or '?'}, antivirus: "
                                     f"{', '.join(st.get('antiviruses') or []) or '?'}. Passwords are not stored here."),
                        severity="critical", matched=t, indicators=[("email", t.value.lower())], published=when))
            time.sleep(1)
        return findings, queries


# ------------------------------------------------------------------ phishing / look-alikes
class CrtShSource(Source):
    name = "crtsh"
    label = "Certificate transparency (crt.sh)"
    description = "New TLS certificates for look-alike domains that contain your brand - early phishing warning"
    needs_key = False
    category = "phishing"
    kinds = ("domain", "brand")
    enable_key = "CRTSH_ENABLED"
    signup = "https://crt.sh/"
    fields = [{"key": "CRTSH_MAX_RESULTS", "label": "Max certificates per term", "type": "int"}]

    def run(self, terms):
        s = self.session()
        own = _own_domains()
        findings, queries = [], 0
        since = datetime.utcnow() - timedelta(days=30)
        for t in terms_of(terms, *self.kinds):
            needle = _label(t.value) if t.kind == "domain" else t.value.lower().replace(" ", "")
            if len(needle) < 4:
                continue
            if t.kind == "domain":
                own = own | {t.value.lower().lstrip("@")}
            queries += 1
            r = s.get("https://crt.sh/", params={"q": f"%{needle}%", "output": "json", "exclude": "expired"},
                      timeout=90)
            if r.status_code >= 400:
                raise SourceError(f"crtsh: HTTP {r.status_code}")
            try:
                rows = r.json()
            except ValueError:
                rows = []
            hosts: dict[str, str] = {}
            for row in rows[: settings.CRTSH_MAX_RESULTS * 3]:
                try:
                    nb = datetime.fromisoformat(str(row.get("not_before", ""))[:19])
                except ValueError:
                    nb = None
                if nb and nb < since:
                    continue
                for h in str(row.get("name_value", "")).lower().split("\n"):
                    h = h.strip().lstrip("*.")
                    if h and needle in h and not _is_own(h, own):
                        hosts.setdefault(h, str(row.get("not_before", ""))[:10])
            if not hosts:
                continue
            top = sorted(hosts)[: settings.CRTSH_MAX_RESULTS]
            findings.append(Finding(
                source=self.name, key=f"crtsh:{needle}:{','.join(top[:15])}",
                title=f"{len(hosts)} look-alike domain(s) with '{needle}' got new certificates",
                description="Certificates issued in the last 30 days for domains that are not on your watchlist:\n"
                            + "\n".join(f"- {h} (from {hosts[h]})" for h in top[:40]),
                severity="medium", matched=t, url=f"https://crt.sh/?q=%25{quote(needle)}%25",
                indicators=[("domain", h) for h in top[:40]], extra={"domains": top}))
            time.sleep(2)
        return findings, queries


class URLScanSource(Source):
    name = "urlscan"
    label = "urlscan.io"
    description = "Recently scanned web pages imitating your brand or domain (phishing kits)"
    category = "phishing"
    kinds = ("domain", "brand")
    signup = "https://urlscan.io/user/signup"
    fields = [{"key": "URLSCAN_API_KEY", "label": "API key"}]

    def run(self, terms):
        s = self.session()
        own = _own_domains()
        h = {"API-Key": settings.URLSCAN_API_KEY}
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            if t.kind == "domain":
                d = t.value.lower().lstrip("@")
                own = own | {d}
                q = f"page.domain:*{_label(d)}* AND NOT page.domain:{d} AND date:>now-30d"
            else:
                q = f'page.title:"{t.value}" AND date:>now-30d'
            queries += 1
            res = self.get_json(s, "https://urlscan.io/api/v1/search/", headers=h, params={"q": q, "size": 100}) or {}
            for it in res.get("results") or []:
                page = it.get("page") or {}
                dom = str(page.get("domain") or "")
                if not dom or _is_own(dom, own):
                    continue
                findings.append(Finding(
                    source=self.name, key=f"urlscan:{dom}",
                    title=f"Possible phishing page {dom} imitates '{t.value}'",
                    description=(f"Scanned {str((it.get('task') or {}).get('time', '?'))[:10]}: {page.get('url')} "
                                 f"(IP {page.get('ip') or '?'}, {page.get('country') or '?'}, "
                                 f"title: {page.get('title') or '-'})."),
                    severity="medium", matched=t, url=it.get("result") or f"https://urlscan.io/search/#{quote(dom)}",
                    indicators=[("domain", dom)] + ([("ip", page["ip"])] if page.get("ip") else [])))
            time.sleep(2)
        return findings, queries


# ------------------------------------------------------------------ pastes
class PsbdmpSource(Source):
    name = "psbdmp"
    label = "Paste dumps (psbdmp)"
    description = "Pastebin dumps that mention your domains, e-mails or brands"
    needs_key = False
    category = "leak"
    kinds = ("domain", "email", "brand", "keyword")
    enable_key = "PSBDMP_ENABLED"
    signup = "https://psbdmp.ws/"

    def run(self, terms):
        s = self.session()
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            res = self.get_json(s, f"https://psbdmp.ws/api/v3/search/{quote(t.value)}", ok404=True) or []
            if isinstance(res, dict):
                res = res.get("data") or []
            for p in res[:25]:
                pid = p.get("id")
                if not pid:
                    continue
                findings.append(Finding(
                    source=self.name, key=f"psbdmp:{pid}:{t.value.lower()}",
                    title=f"Paste {pid} mentions '{t.value}'",
                    description=f"Paste time: {p.get('time', '?')}, length: {p.get('length', '?')}, tags: {p.get('tags') or '-'}.",
                    severity="medium" if t.kind in ("email", "domain") else "low", matched=t,
                    url=f"https://pastebin.com/{pid}", published=str(p.get("time", ""))))
            time.sleep(1)
        return findings, queries


# ------------------------------------------------------------------ breach APIs
class LeakCheckSource(Source):
    name = "leakcheck"
    label = "LeakCheck"
    description = "Breached accounts for your domains / e-mails (7,500+ breaches, combolists, stealer logs)"
    category = "breach"
    kinds = ("domain", "email")
    signup = "https://leakcheck.io/api"
    sample = ("email", "test@example.com")
    fields = [{"key": "LEAKCHECK_API_KEY", "label": "API key (v2)"}]

    def run(self, terms):
        s = self.session()
        h = {"X-API-Key": settings.LEAKCHECK_API_KEY, "Accept": "application/json"}
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            v = t.value.lower().lstrip("@")
            res = self.get_json(s, f"https://leakcheck.io/api/v2/query/{quote(v)}", headers=h,
                                params={"type": "email" if t.kind == "email" else "domain", "limit": 1000},
                                ok404=True) or {}
            if res.get("success") is False and res.get("error") not in (None, "Not found"):
                raise SourceError(f"leakcheck: {res.get('error')}")
            per: dict[str, dict] = {}
            for row in res.get("result") or []:
                src = row.get("source") or {}
                name = src.get("name") or "Unknown"
                e = per.setdefault(name, {"accounts": set(), "password": False, "date": src.get("breach_date") or ""})
                if row.get("email") or row.get("username"):
                    e["accounts"].add(str(row.get("email") or row.get("username")).lower())
                e["password"] |= "password" in (row.get("fields") or []) or bool(row.get("password"))
            for name, e in per.items():
                accts = sorted(e["accounts"])
                findings.append(Finding(
                    source=self.name, key=f"leakcheck:{v}:{name}",
                    title=f"{len(accts) or 1} account(s) for {v} in '{name}'",
                    description=(f"Breach date: {e['date'] or '?'}. Accounts: {', '.join(accts[:25])}"
                                 f"{' …' if len(accts) > 25 else ''}. "
                                 f"{'Passwords exposed (not stored here).' if e['password'] else 'No password field.'}"),
                    severity="high" if e["password"] else "medium", matched=t,
                    indicators=[("email", a) for a in accts[:25] if "@" in a]))
            time.sleep(1)
        return findings, queries


class DeHashedSource(Source):
    name = "dehashed"
    label = "DeHashed"
    description = "Search breach databases for your domains / e-mails (DeHashed v2 API)"
    category = "breach"
    kinds = ("domain", "email")
    signup = "https://app.dehashed.com/documentation/api"
    sample = ("email", "test@example.com")
    fields = [{"key": "DEHASHED_API_KEY", "label": "API key (v2)"}]

    def run(self, terms):
        s = self.session()
        h = {"Dehashed-Api-Key": settings.DEHASHED_API_KEY, "Content-Type": "application/json"}
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            v = t.value.lower().lstrip("@")
            q = f"email:{v}" if t.kind == "email" else f"domain:{v}"
            res = self.get_json(s, "https://api.dehashed.com/v2/search", method="POST", headers=h,
                                json_body={"query": q, "page": 1, "size": 500, "de_dupe": True}) or {}
            per: dict[str, dict] = {}
            for row in res.get("entries") or []:
                db = row.get("database_name") or "Unknown"
                e = per.setdefault(db, {"accounts": set(), "password": False})
                for em in (row.get("email") if isinstance(row.get("email"), list) else [row.get("email")]):
                    if em:
                        e["accounts"].add(str(em).lower())
                e["password"] |= bool(row.get("password") or row.get("hashed_password"))
            for db, e in per.items():
                accts = sorted(e["accounts"])
                findings.append(Finding(
                    source=self.name, key=f"dehashed:{v}:{db}",
                    title=f"{len(accts) or 1} record(s) for {v} in '{db}'",
                    description=(f"Accounts: {', '.join(accts[:25])}{' …' if len(accts) > 25 else ''}. "
                                 f"{'Passwords / hashes exposed (not stored here).' if e['password'] else ''}"),
                    severity="high" if e["password"] else "medium", matched=t,
                    indicators=[("email", a) for a in accts[:25] if "@" in a]))
        return findings, queries


# ------------------------------------------------------------------ exposure
class LeakIXSource(Source):
    name = "leakix"
    label = "LeakIX"
    description = "Exposed services and open databases / leaks on your domains"
    category = "exposure"
    kinds = ("domain",)
    signup = "https://leakix.net/auth/register"
    fields = [{"key": "LEAKIX_API_KEY", "label": "API key"}]

    def run(self, terms):
        s = self.session()
        h = {"api-key": settings.LEAKIX_API_KEY, "Accept": "application/json"}
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            d = t.value.lower().lstrip("@")
            res = self.get_json(s, "https://leakix.net/search", headers=h,
                                params={"scope": "leak", "q": f'+domain:"{d}"', "page": 0}, ok404=True) or []
            for ev in res if isinstance(res, list) else []:
                host, port = ev.get("host") or ev.get("ip") or "?", ev.get("port") or "?"
                leak = ev.get("leak") or {}
                sev = str(leak.get("severity") or "medium").lower()
                findings.append(Finding(
                    source=self.name, key=f"leakix:{host}:{port}:{ev.get('event_source')}",
                    title=f"Exposed {ev.get('event_source') or 'service'} on {host}:{port}",
                    description=(f"{(ev.get('summary') or '')[:600]}\nDataset: "
                                 f"{(leak.get('dataset') or {}).get('rows', '?')} rows. Seen {ev.get('time', '?')}."),
                    severity=sev if sev in ("low", "medium", "high", "critical") else "medium", matched=t,
                    url=f"https://leakix.net/host/{ev.get('ip') or host}",
                    indicators=[("ip", ev["ip"])] if ev.get("ip") else []))
            time.sleep(1)
        return findings, queries


class ShodanSource(Source):
    name = "shodan"
    label = "Shodan"
    description = "Internet-exposed hosts of your domains with known vulnerabilities or risky ports"
    category = "exposure"
    kinds = ("domain",)
    signup = "https://account.shodan.io/"
    fields = [{"key": "SHODAN_API_KEY", "label": "API key"}]
    RISKY = {21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}

    def test(self):
        res = self.get_json(self.session(), "https://api.shodan.io/api-info",
                            params={"key": settings.SHODAN_API_KEY}) or {}
        return {"ok": True, "plan": res.get("plan"), "query_credits": res.get("query_credits")}

    def run(self, terms):
        s = self.session()
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            d = t.value.lower().lstrip("@")
            res = self.get_json(s, "https://api.shodan.io/shodan/host/search",
                                params={"key": settings.SHODAN_API_KEY, "query": f"hostname:{d}", "minify": "true"}) or {}
            for m in res.get("matches") or []:
                vulns = sorted((m.get("vulns") or {}).keys()) if isinstance(m.get("vulns"), dict) else list(m.get("vulns") or [])
                port = m.get("port")
                if not vulns and port not in self.RISKY:
                    continue
                ip = m.get("ip_str")
                findings.append(Finding(
                    source=self.name, key=f"shodan:{ip}:{port}:{','.join(vulns[:5])}",
                    title=f"{', '.join(m.get('hostnames') or [ip])[:80]} exposes port {port}"
                          + (f" with {len(vulns)} known CVE(s)" if vulns else ""),
                    description=(f"{m.get('product') or ''} {m.get('version') or ''} on {ip}:{port} "
                                 f"({(m.get('location') or {}).get('country_name') or '?'}). "
                                 f"CVEs: {', '.join(vulns[:15]) or '-'}."),
                    severity="high" if vulns else "medium", matched=t, url=f"https://www.shodan.io/host/{ip}",
                    indicators=[("ip", ip)] + [("cve", v) for v in vulns[:15]]))
            time.sleep(1)
        return findings, queries


class GitHubSource(Source):
    name = "github"
    label = "GitHub code leaks"
    description = "Public code that mentions your domains together with passwords, tokens or keys"
    category = "leak"
    kinds = ("domain",)
    signup = "https://github.com/settings/tokens"
    fields = [{"key": "GITHUB_SEARCH_TOKEN", "label": "Personal access token",
               "help": "A fine-grained token without any repository permission is enough for code search."}]
    WORDS = ("password", "secret", "api_key", "token")

    def run(self, terms):
        s = self.session()
        h = {"Authorization": f"Bearer {settings.GITHUB_SEARCH_TOKEN}", "Accept": "application/vnd.github+json"}
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            d = t.value.lower().lstrip("@")
            for word in self.WORDS[:2]:
                queries += 1
                res = self.get_json(s, "https://api.github.com/search/code", headers=h,
                                    params={"q": f'"{d}" {word}', "per_page": 30}) or {}
                for it in res.get("items") or []:
                    repo = (it.get("repository") or {}).get("full_name", "?")
                    findings.append(Finding(
                        source=self.name, key=f"github:{repo}:{it.get('path')}",
                        title=f"Possible secret for {d} in {repo}/{it.get('path')}",
                        description=f"Public file mentions '{d}' and '{word}'. Review and ask the owner to remove it; "
                                    "rotate any credential that is real.",
                        severity="high", matched=t, url=it.get("html_url", "")))
                time.sleep(7)  # code search: 10 requests / minute
        return findings, queries
