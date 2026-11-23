"""Runs external intelligence sources against the watchlist."""
from __future__ import annotations

import logging

from ..ai.router import get_router
from ..alerts.service import dedup_key, raise_alert
from ..storage.db import audit, session_scope
from ..storage.models import Indicator, SourceRun, WatchItem, utcnow
from ..tasks import create_task, _clean
from ..watchlist import WatchTerm
from .ahmia import AhmiaSource
from .hibp import HIBPSource
from .intelx import IntelXSource
from .ransomware import RansomwareLiveSource

logger = logging.getLogger(__name__)

SOURCES = [HIBPSource(), IntelXSource(), RansomwareLiveSource(), AhmiaSource()]


def get_source(name: str):
    for s in SOURCES:
        if s.name == name:
            return s
    raise KeyError(name)


def source_status() -> list[dict]:
    out = []
    with session_scope() as s:
        for src in SOURCES:
            last = s.query(SourceRun).filter_by(source=src.name).order_by(SourceRun.id.desc()).first()
            out.append({"name": src.name, "label": src.label, "description": src.description,
                        "enabled": src.enabled(), "needs_key": src.needs_key,
                        "last_run": None if not last else {
                            "status": last.status, "started": last.started_at.isoformat() + "Z", "findings": last.findings,
                            "alerts": last.alerts, "error": last.error}})
    return out


def run_source(name: str) -> dict:
    src = get_source(name)
    with session_scope() as s:
        terms = [WatchTerm(w.kind, w.value, w.severity, w.id) for w in s.query(WatchItem).filter_by(active=True)]
        sr = SourceRun(source=name)
        s.add(sr)
        s.flush()
        sr_id = sr.id
    if not src.enabled():
        status, err, findings, queries = "skipped", "not configured", [], 0
    else:
        try:
            findings, queries = src.run(terms)
            status, err = "done", ""
        except Exception as e:  # noqa: BLE001
            logger.exception("source %s failed", name)
            findings, queries, status, err = [], 0, "failed", str(e)[:1000]
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
            "findings": len(findings), "alerts": alerts}


def run_all_sources() -> list[dict]:
    return [run_source(s.name) for s in SOURCES if s.enabled()]
