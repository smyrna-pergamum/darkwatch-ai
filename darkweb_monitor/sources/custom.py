"""User-defined API sources: any HTTP JSON API that can be searched with a
term (e.g. a commercial dark-web / leak API your company already pays for).

Definition (stored in data/intel_sources.json, created from the dashboard):
    name          slug, unique
    label         display name
    url           request URL; {term} and {key} are replaced (URL-encoded)
    method        GET | POST
    body          optional JSON body template for POST ({term} replaced)
    header_name   header carrying the API key (e.g. X-API-Key, Authorization)
    header_prefix e.g. "Bearer " (optional)
    api_key       secret, never sent back to the browser
    kinds         watch-term kinds to query (domain, email, brand, keyword, ip, crypto)
    results_path  dot path to the result list in the JSON ("data.items"; empty = the response itself)
    title_field / url_field / id_field / date_field   fields of one result (dot paths)
    severity      severity of findings
"""
from __future__ import annotations

import json
import re
from urllib.parse import quote

from .base import Finding, Source, SourceError, terms_of

SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{1,40}$")
TERM_KINDS = ("domain", "email", "brand", "keyword", "ip", "crypto")


def dig(obj, path: str):
    if not path:
        return obj
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.isdigit() and int(part) < len(obj):
            obj = obj[int(part)]
        else:
            return None
    return obj


def validate_custom(d: dict) -> dict:
    name = str(d.get("name", "")).strip().lower()
    if not SLUG.match(name):
        raise ValueError("name: 2-41 characters, a-z 0-9 _ -")
    url = str(d.get("url", "")).strip()
    if not url.startswith(("https://", "http://")) or "{term}" not in url + str(d.get("body", "")):
        raise ValueError("url must start with http(s):// and {term} must appear in the URL or body")
    method = str(d.get("method", "GET")).upper()
    if method not in ("GET", "POST"):
        raise ValueError("method must be GET or POST")
    body = str(d.get("body", "") or "")
    if body:
        try:
            json.loads(body.replace("{term}", "x").replace("{key}", "x"))
        except ValueError as e:
            raise ValueError(f"body is not valid JSON: {e}") from e
    kinds = [k for k in (d.get("kinds") or ["domain", "email", "brand"]) if k in TERM_KINDS] or ["domain"]
    sev = d.get("severity") if d.get("severity") in ("low", "medium", "high", "critical") else "medium"
    return {"name": name, "label": str(d.get("label") or name)[:80], "url": url[:500], "method": method,
            "body": body[:2000], "header_name": str(d.get("header_name") or "")[:80],
            "header_prefix": str(d.get("header_prefix") or "")[:20], "api_key": str(d.get("api_key") or ""),
            "kinds": kinds, "results_path": str(d.get("results_path") or "")[:120],
            "title_field": str(d.get("title_field") or "")[:120], "url_field": str(d.get("url_field") or "")[:120],
            "id_field": str(d.get("id_field") or "")[:120], "date_field": str(d.get("date_field") or "")[:120],
            "severity": sev, "enabled": bool(d.get("enabled", True)),
            "description": str(d.get("description") or "")[:300]}


class CustomSource(Source):
    category = "custom"
    needs_key = False

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.name = "custom:" + cfg["name"]
        self.label = cfg.get("label") or cfg["name"]
        self.description = cfg.get("description") or f"Custom API · {cfg.get('url', '')[:60]}"
        self.kinds = tuple(cfg.get("kinds") or ("domain",))
        self.sample = (self.kinds[0], "test@example.com" if self.kinds[0] == "email" else "example.com")

    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True))

    def info(self) -> dict:
        public = {k: v for k, v in self.cfg.items() if k != "api_key"}
        public["api_key_set"] = bool(self.cfg.get("api_key"))
        return {"name": self.name, "label": self.label, "description": self.description, "needs_key": False,
                "category": "custom", "kinds": list(self.kinds), "enable_key": "", "signup": "", "via_tor": False,
                "custom": True, "config": public, "fields": []}

    def request(self, s, term: str):
        c = self.cfg
        key = c.get("api_key", "")
        url = c["url"].replace("{term}", quote(term, safe="")).replace("{key}", quote(key, safe=""))
        headers = {"Accept": "application/json"}
        if c.get("header_name") and key:
            headers[c["header_name"]] = f"{c.get('header_prefix', '')}{key}"
        body = None
        if c.get("method") == "POST" and c.get("body"):
            body = json.loads(c["body"].replace("{term}", json.dumps(term)[1:-1]).replace("{key}", key))
        return self.get_json(s, url, method=c.get("method", "GET"), headers=headers, json_body=body, ok404=True)

    def run(self, terms):
        s = self.session()
        c = self.cfg
        findings, queries = [], 0
        for t in terms_of(terms, *self.kinds):
            queries += 1
            data = self.request(s, t.value)
            items = dig(data, c.get("results_path", ""))
            if items is None:
                continue
            if isinstance(items, dict):
                items = [items]
            if not isinstance(items, list):
                raise SourceError(f"{self.name}: results_path does not point to a list")
            for i, it in enumerate(items[:50]):
                ident = dig(it, c.get("id_field", "")) if c.get("id_field") else None
                title = dig(it, c.get("title_field", "")) if c.get("title_field") else None
                ident = str(ident if ident is not None else (title or i))
                findings.append(Finding(
                    source=self.name, key=f"{self.name}:{t.value.lower()}:{ident}",
                    title=f"{self.label}: {str(title)[:200] if title else f'result for {t.value!r}'}",
                    description=json.dumps(it, ensure_ascii=False, default=str)[:1500] if not isinstance(it, str) else it[:1500],
                    severity=c.get("severity", "medium"), matched=t,
                    url=str(dig(it, c["url_field"]) or "") if c.get("url_field") else "",
                    published=str(dig(it, c["date_field"]) or "") if c.get("date_field") else ""))
        return findings, queries
