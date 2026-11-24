"""Runs external intelligence sources against the watchlist."""
from __future__ import annotations

import logging
import re

from ..ai.router import get_router
from ..alerts.service import dedup_key, raise_alert
from ..storage.db import audit, session_scope
from ..storage.models import Indicator, SourceRun, WatchItem, utcnow
from ..tasks import create_task, _clean
from ..watchlist import WatchTerm
from .ahmia import AhmiaSource
from .base import Finding
from .custom import CustomSource
from .extra import (
    CrtShSource, DeHashedSource, GitHubSource, HudsonRockSource, LeakCheckSource, LeakIXSource, PsbdmpSource,
    ShodanSource, URLScanSource,
)
from .hibp import HIBPSource
from .intelx import IntelXSource
from .onionsearch import OnionSearchSource
from .ransomware import RansomwareLiveSource

logger = logging.getLogger(__name__)

SOURCES = [HIBPSource(), IntelXSource(), RansomwareLiveSource(), AhmiaSource(), OnionSearchSource(),
           HudsonRockSource(), LeakCheckSource(), DeHashedSource(), CrtShSource(), URLScanSource(),
           PsbdmpSource(), LeakIXSource(), ShodanSource(), GitHubSource()]
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def all_sources() -> list:
    from config.intel_store import custom_sources
    return SOURCES + [CustomSource(c) for c in custom_sources()]


def get_source(name: str):
    for s in all_sources():
        if s.name == name:
            return s
    raise KeyError(name)


def source_status() -> list[dict]:
    out = []
    with session_scope() as s:
        for src in all_sources():
            last = s.query(SourceRun).filter_by(source=src.name).order_by(SourceRun.id.desc()).first()
            out.append({**src.info(), "enabled": src.enabled(),
                        "last_run": None if not last else {
                            "status": last.status, "started": last.started_at.isoformat() + "Z", "findings": last.findings,
                            "alerts": last.alerts, "error": last.error}})
    return out


def infer_term(value: str, kind: str | None = None) -> WatchTerm:
    v = value.strip().strip('"').strip("'")
    if not kind:
        kind = ("email" if _EMAIL.match(v) else "ip" if _IP.match(v) else
                "domain" if _DOMAIN.match(v) and " " not in v else "brand")
    return WatchTerm(kind, v, "medium", None)


def finding_dict(f: Finding) -> dict:
    return {"source": f.source, "title": f.title, "description": f.description[:1500], "severity": f.severity,
            "url": f.url, "published": f.published, "term": f.matched.value if f.matched else None,
            "onions": f.discovered_onions[:20], "extra": f.extra}


def _execute(src, terms: list[WatchTerm]) -> tuple[list[Finding], int, str, str]:
    if not src.enabled():
        return [], 0, "skipped", "not configured - add the API key / switch it on under Intel sources"
    try:
        findings, queries = src.run(terms)
        return findings, queries, "done", ""
    except Exception as e:  # noqa: BLE001
        logger.warning("source %s failed: %s", src.name, e)
        return [], 0, "failed", short_error(e)


def short_error(e: Exception) -> str:
    """Readable one-liner instead of urllib3's nested retry message."""
    import requests
    if isinstance(e, requests.RequestException):
        req = getattr(e, "request", None)
        host = ""
        if req is not None and getattr(req, "url", None):
            from urllib.parse import urlparse
            host = urlparse(req.url).hostname or ""
        txt = str(e)
        why = ("proxy refused the connection" if "ProxyError" in txt or "Tunnel connection failed" in txt else
               "timed out" if isinstance(e, requests.Timeout) else
               "name could not be resolved" if "NameResolution" in txt or "getaddrinfo" in txt else
               "connection failed" if isinstance(e, requests.ConnectionError) else type(e).__name__)
        return f"cannot reach {host or 'the API'}: {why}"[:1000]
    return str(e)[:1000]


def query(values: list[str], names: list[str] | None = None, save: bool = False,
          kind: str | None = None) -> dict:
    """Ad-hoc search: any terms (not only the watchlist) against chosen sources.
    Results are returned; with ``save`` they are also stored as alerts."""
    terms = [infer_term(v, kind) for v in values if v and v.strip()][:10]
    if not terms:
        raise ValueError("no search terms")
    srcs = [get_source(n) for n in names] if names else [x for x in all_sources() if x.enabled()]
    out = []
    for src in srcs:
        usable = [t for t in terms if not src.kinds or t.kind in src.kinds
                  or (t.kind == "brand" and "keyword" in src.kinds)]
        if not usable:
            out.append({"source": src.name, "label": src.label, "status": "skipped",
                        "error": f"accepts {', '.join(src.kinds)} terms", "findings": []})
            continue
        if save:
            res = run_source(src.name, terms=usable)
            items = res.pop("items", [])
            out.append({**res, "label": src.label, "alerts": res.get("alerts", 0), "findings": items})
            continue
        findings, queries, status, err = _execute(src, usable)
        out.append({"source": src.name, "label": src.label, "status": status, "error": err, "queries": queries,
                    "findings": [finding_dict(f) for f in findings[:50]]})
    audit("source.query", f"ad-hoc {[t.value for t in terms]} -> {[o['source'] for o in out]} save={save}")
    return {"terms": [{"kind": t.kind, "value": t.value} for t in terms], "results": out}


def run_source(name: str, terms: list[WatchTerm] | None = None) -> dict:
    src = get_source(name)
    with session_scope() as s:
        if terms is None:
            terms = [WatchTerm(w.kind, w.value, w.severity, w.id) for w in s.query(WatchItem).filter_by(active=True)]
        sr = SourceRun(source=name)
        s.add(sr)
        s.flush()
        sr_id = sr.id
    findings, queries, status, err = _execute(src, terms)
    alerts = 0
    router = get_router()
    with session_scope() as s:
        for f in findings:
            sev = f.severity
            if f.matched and f.matched.severity == "critical":
                sev = "critical"
            matches = [{"kind": f.matched.kind, "value": f.matched.value, "severity": f.matched.severity,
                        "id": f.matched.id, "context": f.title}] if f.matched else []
            _, created = raise_alert(s, source=f.source, key=dedup_key(f.source, f.key), title=f.title,
                                     description=f.description + (f"\nPublished: {f.published}" if f.published else ""),
                                     severity=sev, url=f.url, matches=matches,
                                     iocs=[v for _, v in f.indicators], router=router)
            alerts += int(created)
            for it, val in f.indicators:
                ind = s.query(Indicator).filter_by(ioc_type=it, value=val).first()
                if not ind:
                    ind = Indicator(ioc_type=it, value=val, seen_count=0, on_watchlist=True)
                    s.add(ind)
                ind.last_seen, ind.seen_count = utcnow(), (ind.seen_count or 0) + 1
                ind.tags = ",".join(sorted(set(filter(None, (ind.tags or "").split(","))) | {f.source}))
        sr = s.get(SourceRun, sr_id)
        sr.finished_at, sr.status, sr.error = utcnow(), status, err
        sr.queries, sr.findings, sr.alerts = queries, len(findings), alerts
    for f in findings:
        for url in f.discovered_onions:
            c = _clean({"kind": "add_target", "title": f"Monitor onion found by {src.label}",
                        "reason": f.title, "priority": "low",
                        "payload": {"url": url, "mode": "smart",
                                    "goal": f"Find mentions of {f.matched.value if f.matched else 'watch terms'}"}},
                       None, None)
            if c:
                create_task(c, source="rule")
    audit("source.run", f"{name} {status} findings={len(findings)} alerts={alerts}")
    return {"source": name, "status": status, "error": err, "queries": queries,
            "findings": len(findings), "alerts": alerts, "items": [finding_dict(f) for f in findings[:50]]}


def run_all_sources() -> list[dict]:
    return [run_source(s.name) for s in all_sources() if s.enabled()]
