"""API routes."""
from __future__ import annotations

import json
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import func

from config.settings import settings
from ..storage.db import session_scope, init_db
from ..storage.models import Target, Page, IOC, Alert, CrawlRun
from ..pipeline import run_crawl
from ..ai.router import AIRouter

router = APIRouter()
_ai = AIRouter()


class TargetIn(BaseModel):
    url: str
    label: str = ""
    keywords: str = ""


class CrawlIn(BaseModel):
    url: str
    keywords: str = ""
    depth: int = None


@router.on_event("startup")
def _startup():
    init_db()


def _ai_status():
    return _ai.status()


@router.get("/status")
def status():
    return {"ai": _ai.status(), "tor_proxy": f"{settings.TOR_PROXY_HOST}:{settings.TOR_PROXY_PORT}"}


@router.get("/targets")
def list_targets():
    with session_scope() as s:
        rows = s.query(Target).all()
        return [{"id": t.id, "url": t.url, "label": t.label, "keywords": t.keywords,
                 "active": t.active, "last_crawled": str(t.last_crawled)} for t in rows]


@router.post("/targets")
def add_target(t: TargetIn):
    with session_scope() as s:
        existing = s.query(Target).filter_by(url=t.url).first()
        if existing:
            existing.label = t.label or existing.label
            existing.keywords = t.keywords or existing.keywords
            return {"id": existing.id}
        nt = Target(url=t.url, label=t.label, keywords=t.keywords)
        s.add(nt)
        s.flush()
        return {"id": nt.id}


@router.delete("/targets/{tid}")
def del_target(tid: int):
    with session_scope() as s:
        t = s.query(Target).filter_by(id=tid).first()
        if not t:
            raise HTTPException(404, "not found")
        s.delete(t)
    return {"ok": True}


@router.post("/crawl")
def crawl_now(c: CrawlIn, bg: BackgroundTasks):
    # run synchronously for local dev simplicity
    res = run_crawl(c.url, keywords=c.keywords, depth=c.depth)
    return res


@router.get("/pages")
def list_pages(limit: int = 50):
    with session_scope() as s:
        rows = s.query(Page).order_by(Page.crawled_at.desc()).limit(limit).all()
        return [{"id": p.id, "url": p.url, "title": p.title, "severity": p.ai_severity,
                 "summary": p.ai_summary, "crawled_at": str(p.crawled_at)} for p in rows]


@router.get("/pages/{pid}")
def get_page(pid: int):
    with session_scope() as s:
        p = s.query(Page).filter_by(id=pid).first()
        if not p:
            raise HTTPException(404, "not found")
        return {"id": p.id, "url": p.url, "title": p.title, "content": p.content,
                "severity": p.ai_severity, "summary": p.ai_summary, "crawled_at": str(p.crawled_at)}


@router.get("/iocs")
def list_iocs(limit: int = 100, ioc_type: str = None):
    with session_scope() as s:
        q = s.query(IOC)
        if ioc_type:
            q = q.filter_by(ioc_type=ioc_type)
        rows = q.order_by(IOC.created_at.desc()).limit(limit).all()
        return [{"id": i.id, "type": i.ioc_type, "value": i.value, "confidence": i.confidence,
                 "page_id": i.page_id, "created_at": str(i.created_at)} for i in rows]


@router.get("/alerts")
def list_alerts(limit: int = 50):
    with session_scope() as s:
        rows = s.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
        return [{"id": a.id, "severity": a.severity, "title": a.title,
                 "description": a.description, "notified": a.notified,
                 "created_at": str(a.created_at), "page_id": a.page_id} for a in rows]


@router.get("/stats")
def stats():
    with session_scope() as s:
        return {
            "targets": s.query(func.count(Target.id)).scalar(),
            "pages": s.query(func.count(Page.id)).scalar(),
            "iocs": s.query(func.count(IOC.id)).scalar(),
            "alerts": s.query(func.count(Alert.id)).scalar(),
            "runs": s.query(func.count(CrawlRun.id)).scalar(),
        }


@router.get("/runs")
def runs(limit: int = 20):
    with session_scope() as s:
        rows = s.query(CrawlRun).order_by(CrawlRun.started_at.desc()).limit(limit).all()
        return [{"id": r.id, "started": str(r.started_at), "finished": str(r.finished_at),
                 "pages": r.pages_crawled, "iocs": r.iocs_found, "alerts": r.alerts_raised,
                 "status": r.status, "ai_summary": _parse_run_summary(r.ai_summary)} for r in rows]


def _parse_run_summary(raw):
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


@router.get("/runs/{rid}")
def get_run(rid: int):
    with session_scope() as s:
        r = s.query(CrawlRun).filter_by(id=rid).first()
        if not r:
            raise HTTPException(404, "not found")
        return {
            "id": r.id,
            "started": str(r.started_at),
            "finished": str(r.finished_at),
            "pages": r.pages_crawled,
            "iocs": r.iocs_found,
            "alerts": r.alerts_raised,
            "status": r.status,
            "ai_summary": _parse_run_summary(r.ai_summary),
        }