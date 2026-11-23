"""REST API."""
from __future__ import annotations

import hmac
import json
from datetime import timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_

from config.settings import settings
from .. import __version__
from ..ai.router import get_router
from ..alerts.notifier import Notifier
from ..crawler.parsers import is_onion, normalize_url
from ..crawler.tor_client import new_identity, tor_status
from ..storage.db import audit, session_scope
from ..storage.models import (
    SEVERITIES, AgentApproval, Alert, AuditLog, CrawlRun, Indicator, Page, Sighting, SourceRun, Target, Task,
    WatchItem, utcnow,
)
from ..watchlist import KINDS as WATCH_KINDS, validate as validate_watch


def require_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not settings.API_KEY:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(401, "invalid or missing X-API-Key")


router = APIRouter(dependencies=[Depends(require_key)])

Mode = Literal["standard", "smart", "agent"]
Scope = Literal["same_site", "allowed", "any_onion"]
Sev = Literal["low", "medium", "high", "critical"]


def _iso(dt) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _json(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def check_cron(v: str | None) -> str:
    v = (v or "").strip()
    if v:
        from apscheduler.triggers.cron import CronTrigger
        try:
            CronTrigger.from_crontab(v)
        except ValueError as e:
            raise ValueError(f"invalid cron expression: {e}") from e
    return v


# ------------------------------------------------------------------ schemas
class TargetIn(BaseModel):
    url: str
    label: str = ""
    keywords: str = ""
    crawl_mode: Mode = "standard"
    agent_goal: str = ""
    depth: Optional[int] = Field(default=None, ge=0, le=6)
    max_pages: Optional[int] = Field(default=None, ge=1, le=2000)
    scope: Optional[Scope] = None
    schedule_interval_min: Optional[int] = Field(default=None, ge=0, le=60 * 24 * 30)
    schedule_cron: str = ""
    active: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        return normalize_url(v)

    @field_validator("schedule_cron")
    @classmethod
    def _cron(cls, v: str) -> str:
        return check_cron(v)


class TargetPatch(BaseModel):
    label: Optional[str] = None
    keywords: Optional[str] = None
    crawl_mode: Optional[Mode] = None
    agent_goal: Optional[str] = None
    depth: Optional[int] = Field(default=None, ge=0, le=6)
    max_pages: Optional[int] = Field(default=None, ge=1, le=2000)
    scope: Optional[Scope] = None
    schedule_interval_min: Optional[int] = Field(default=None, ge=0, le=60 * 24 * 30)
    schedule_cron: Optional[str] = None
    active: Optional[bool] = None
    approval: Optional[Literal["approved", "pending"]] = None


class CrawlIn(BaseModel):
    url: Optional[str] = None
    target_id: Optional[int] = None
    keywords: str = ""
    depth: Optional[int] = Field(default=None, ge=0, le=6)
    max_pages: Optional[int] = Field(default=None, ge=1, le=2000)
    mode: Optional[Mode] = None
    goal: Optional[str] = None


class WatchIn(BaseModel):
    kind: str = "keyword"
    value: str
    severity: Sev = "medium"
    note: str = ""
    active: bool = True


class WatchPatch(BaseModel):
    severity: Optional[Sev] = None
    note: Optional[str] = None
    active: Optional[bool] = None


class AlertPatch(BaseModel):
    status: Optional[Literal["new", "acknowledged", "resolved", "false_positive"]] = None
    analyst_note: Optional[str] = None
    severity: Optional[Sev] = None


class AlertBulk(BaseModel):
    ids: list[int]
    status: Literal["new", "acknowledged", "resolved", "false_positive"]


class TaskIn(BaseModel):
    kind: Literal["recrawl", "add_target", "add_watch", "review"]
    title: str = ""
    reason: str = ""
    payload: dict = {}
    target_id: Optional[int] = None
    priority: Literal["low", "medium", "high"] = "medium"


# ---------------------------------------------------------------- serialisers
def target_dict(t: Target, next_runs: dict | None = None) -> dict:
    return {"id": t.id, "url": t.url, "label": t.label, "keywords": t.keywords, "active": t.active,
            "approval": t.approval, "source": t.source, "crawl_mode": t.crawl_mode,
            "agent_goal": t.agent_goal, "depth": t.depth, "max_pages": t.max_pages, "scope": t.scope,
            "schedule_interval_min": t.schedule_interval_min, "schedule_cron": t.schedule_cron,
            "last_crawled": _iso(t.last_crawled), "last_status": t.last_status, "last_error": t.last_error,
            "created_at": _iso(t.created_at), "is_onion": is_onion(t.url),
            "next_run": (next_runs or {}).get(t.id)}


def run_dict(r: CrawlRun, full: bool = False) -> dict:
    d = {"id": r.id, "target_id": r.target_id, "start_url": r.start_url, "mode": r.mode,
         "trigger": r.trigger, "started": _iso(r.started_at), "finished": _iso(r.finished_at),
         "pages": r.pages_crawled, "changed": r.pages_changed, "iocs": r.iocs_found,
         "alerts": r.alerts_raised, "status": r.status, "error": r.error,
         "ai_summary": _json(r.ai_summary)}
    if full:
        d["agent_log"] = r.agent_log or []
        d["notes"] = _json(r.notes)
    return d


def alert_dict(a: Alert) -> dict:
    return {"id": a.id, "source": a.source, "severity": a.severity, "title": a.title,
            "description": a.description, "url": a.url, "status": a.status, "matches": a.matches or [],
            "occurrences": a.occurrences, "notified": a.notified, "notify_channels": a.notify_channels,
            "triage": a.triage or {}, "analyst_note": a.analyst_note, "page_id": a.page_id,
            "target_id": a.target_id, "run_id": a.run_id, "created_at": _iso(a.created_at),
            "last_seen": _iso(a.last_seen), "threat_class": a.threat_class or "",
            "risk_score": a.risk_score or 0, "risk_factors": a.risk_factors or [],
            "incident_ref": a.incident_ref or ""}


def page_dict(p: Page, content: bool = False) -> dict:
    d = {"id": p.id, "target_id": p.target_id, "run_id": p.run_id, "url": p.url, "title": p.title,
         "severity": p.ai_severity, "category": p.ai_category, "summary": p.ai_summary,
         "ai_analyzed": p.ai_analyzed, "changed": p.changed, "status_code": p.status_code,
         "depth": p.depth, "crawled_at": _iso(p.crawled_at), "first_seen": _iso(p.first_seen),
         "content_hash": p.content_hash, "content_purged": p.content_purged}
    if content:
        d["content"] = p.content
        d["change_summary"] = p.change_summary or {}
    return d


def indicator_dict(i: Indicator) -> dict:
    return {"id": i.id, "type": i.ioc_type, "value": i.value, "first_seen": _iso(i.first_seen),
            "last_seen": _iso(i.last_seen), "seen_count": i.seen_count, "confidence": i.confidence,
            "on_watchlist": i.on_watchlist, "tags": i.tags}


def task_dict(t: Task) -> dict:
    return {"id": t.id, "kind": t.kind, "title": t.title, "reason": t.reason, "payload": t.payload or {},
            "priority": t.priority, "status": t.status, "source": t.source, "target_id": t.target_id,
            "run_id": t.run_id, "due_at": _iso(t.due_at), "result": t.result,
            "created_at": _iso(t.created_at), "updated_at": _iso(t.updated_at)}


def watch_dict(w: WatchItem) -> dict:
    return {"id": w.id, "kind": w.kind, "value": w.value, "severity": w.severity, "note": w.note,
            "active": w.active, "source": w.source, "created_at": _iso(w.created_at)}


def _page(q, limit: int, offset: int, fn):
    total = q.order_by(None).count()
    return {"total": total, "items": [fn(x) for x in q.limit(limit).offset(offset).all()]}


def _resync():
    try:
        from ..scheduler.jobs import sync_jobs
        sync_jobs()
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------- system
@router.get("/status")
def status(force_tor: bool = False):
    from ..runner import get_manager
    from ..scheduler.jobs import jobs_overview, scheduler_running
    from ..sources.feeds import lookup_services
    from ..sources.runner import source_status
    return {"version": __version__, "tor": tor_status(force=force_tor), "ai": get_router().status(),
            "scheduler": {"running": scheduler_running(), "jobs": jobs_overview()},
            "active_runs": get_manager().active_ids(), "sources": source_status(),
            "enrichment": lookup_services(), "misp": bool(settings.MISP_URL and settings.MISP_API_KEY),
            "incidentforge": bool(settings.INCIDENTFORGE_URL),
            "config": {"scope": settings.CRAWL_SCOPE, "tor_required": settings.TOR_REQUIRED,
                       "retention_days": settings.RETENTION_DAYS, "store_content": settings.STORE_PAGE_CONTENT,
                       "alert_min_severity": settings.ALERT_MIN_SEVERITY,
                       "auth": bool(settings.API_KEY),
                       "notify_channels": Notifier().channels(),
                       "auto_approve": settings.list_of("AUTO_APPROVE_TASKS")}}


@router.post("/tor/newnym")
def tor_newnym():
    ok, msg = new_identity()
    audit("tor.newnym", msg)
    return {"ok": ok, "message": msg}


@router.get("/stats")
def stats(days: int = Query(14, ge=1, le=180)):
    since = utcnow() - timedelta(days=days)
    with session_scope() as s:
        def per_day(model, col, extra=None):
            q = s.query(func.date(col), func.count(model.id)).filter(col >= since)
            if extra is not None:
                q = q.filter(extra)
            return {str(d): c for d, c in q.group_by(func.date(col)).all()}
        sev = dict(s.query(Alert.severity, func.count(Alert.id)).filter(
            Alert.status.in_(("new", "acknowledged"))).group_by(Alert.severity).all())
        by_source = dict(s.query(Alert.source, func.count(Alert.id)).group_by(Alert.source).all())
        ioc_types = dict(s.query(Indicator.ioc_type, func.count(Indicator.id)).group_by(Indicator.ioc_type).all())
        cats = dict(s.query(Page.ai_category, func.count(Page.id)).group_by(Page.ai_category).all())
        return {
            "targets": s.query(func.count(Target.id)).scalar(),
            "targets_active": s.query(func.count(Target.id)).filter(Target.active.is_(True)).scalar(),
            "targets_down": s.query(func.count(Target.id)).filter(Target.last_status == "down").scalar(),
            "pages": s.query(func.count(Page.id)).scalar(),
            "indicators": s.query(func.count(Indicator.id)).scalar(),
            "indicators_watch": s.query(func.count(Indicator.id)).filter(Indicator.on_watchlist.is_(True)).scalar(),
            "alerts": s.query(func.count(Alert.id)).scalar(),
            "alerts_open": s.query(func.count(Alert.id)).filter(Alert.status.in_(("new", "acknowledged"))).scalar(),
            "alerts_new": s.query(func.count(Alert.id)).filter(Alert.status == "new").scalar(),
            "runs": s.query(func.count(CrawlRun.id)).scalar(),
            "tasks_proposed": s.query(func.count(Task.id)).filter(Task.status == "proposed").scalar(),
            "approvals_pending": s.query(func.count(AgentApproval.id)).filter(AgentApproval.status == "pending").scalar(),
            "watchlist": s.query(func.count(WatchItem.id)).filter(WatchItem.active.is_(True)).scalar(),
            "open_by_severity": {k: sev.get(k, 0) for k in SEVERITIES},
            "alerts_by_source": by_source, "ioc_types": ioc_types, "categories": cats,
            "series": {"days": days,
                       "alerts": per_day(Alert, Alert.created_at),
                       "pages": per_day(Page, Page.crawled_at),
                       "indicators": per_day(Indicator, Indicator.first_seen)},
        }


@router.get("/search")
def search(q: str = Query(..., min_length=2), limit: int = Query(20, le=100)):
    like = f"%{q}%"
    with session_scope() as s:
        return {
            "pages": [page_dict(p) for p in s.query(Page).filter(or_(
                Page.title.ilike(like), Page.url.ilike(like), Page.content.ilike(like),
                Page.ai_summary.ilike(like))).order_by(Page.crawled_at.desc()).limit(limit)],
            "indicators": [indicator_dict(i) for i in s.query(Indicator).filter(Indicator.value.ilike(like))
                           .order_by(Indicator.last_seen.desc()).limit(limit)],
            "alerts": [alert_dict(a) for a in s.query(Alert).filter(or_(
                Alert.title.ilike(like), Alert.description.ilike(like))).order_by(Alert.id.desc()).limit(limit)],
        }


@router.get("/audit")
def audit_log(limit: int = Query(100, le=1000), offset: int = 0):
    with session_scope() as s:
        q = s.query(AuditLog).order_by(AuditLog.id.desc())
        return _page(q, limit, offset, lambda a: {"id": a.id, "ts": _iso(a.ts), "actor": a.actor,
                                                  "action": a.action, "detail": a.detail})


# ---------------------------------------------------------------- targets
@router.get("/targets")
def list_targets(approval: Optional[str] = None):
    from ..scheduler.jobs import next_runs
    nr = next_runs()
    with session_scope() as s:
        q = s.query(Target).order_by(Target.id.desc())
        if approval:
            q = q.filter_by(approval=approval)
        return [target_dict(t, nr) for t in q.all()]


@router.post("/targets", status_code=201)
def add_target(t: TargetIn):
    with session_scope() as s:
        if s.query(Target).filter_by(url=t.url).first():
            raise HTTPException(409, "target already exists")
        nt = Target(**t.model_dump())
        s.add(nt)
        s.flush()
        out = target_dict(nt)
    audit("target.add", t.url, actor="api")
    _resync()
    return out


@router.patch("/targets/{tid}")
def patch_target(tid: int, p: TargetPatch):
    data = p.model_dump(exclude_unset=True)
    if data.get("schedule_cron"):
        try:
            data["schedule_cron"] = check_cron(data["schedule_cron"])
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
    with session_scope() as s:
        t = s.get(Target, tid)
        if not t:
            raise HTTPException(404, "not found")
        for k, v in data.items():
            setattr(t, k, v)
        out = target_dict(t)
    audit("target.update", f"{tid} {sorted(data)}", actor="api")
    _resync()
    return out


@router.delete("/targets/{tid}")
def del_target(tid: int, purge: bool = False):
    with session_scope() as s:
        t = s.get(Target, tid)
        if not t:
            raise HTTPException(404, "not found")
        if purge:
            s.delete(t)
        else:
            t.active = False
    audit("target.delete" if purge else "target.disable", str(tid), actor="api")
    _resync()
    return {"ok": True}


@router.post("/targets/{tid}/crawl", status_code=202)
def crawl_target(tid: int):
    from ..runner import get_manager
    try:
        rid = get_manager().submit(target_id=tid, trigger="api")
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"run_id": rid}


# ---------------------------------------------------------------- crawl / runs
@router.post("/crawl", status_code=202)
def crawl_now(c: CrawlIn):
    from ..runner import get_manager
    url = c.url
    if url and not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        rid = get_manager().submit(target_id=c.target_id, url=url, keywords=c.keywords, depth=c.depth,
                                   mode=c.mode, goal=c.goal, max_pages=c.max_pages, trigger="api")
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"run_id": rid, "status": "queued"}


@router.get("/runs")
def runs(limit: int = Query(30, le=200), offset: int = 0, target_id: Optional[int] = None,
         status: Optional[str] = None):
    with session_scope() as s:
        q = s.query(CrawlRun).order_by(CrawlRun.id.desc())
        if target_id:
            q = q.filter_by(target_id=target_id)
        if status:
            q = q.filter_by(status=status)
        return _page(q, limit, offset, run_dict)


@router.get("/runs/{rid}")
def get_run(rid: int):
    with session_scope() as s:
        r = s.get(CrawlRun, rid)
        if not r:
            raise HTTPException(404, "not found")
        d = run_dict(r, full=True)
        d["pages_list"] = [page_dict(p) for p in s.query(Page).filter_by(run_id=rid).order_by(Page.id).limit(500)]
        d["alerts_list"] = [alert_dict(a) for a in s.query(Alert).filter_by(run_id=rid).order_by(Alert.id)]
        d["tasks_list"] = [task_dict(t) for t in s.query(Task).filter_by(run_id=rid)]
        return d


@router.post("/runs/{rid}/cancel")
def cancel_run(rid: int):
    from ..runner import get_manager
    ok = get_manager().cancel(rid)
    audit("run.cancel", str(rid), actor="api")
    return {"ok": ok}


# ---------------------------------------------------------------- pages
@router.get("/pages")
def list_pages(limit: int = Query(50, le=500), offset: int = 0, q: Optional[str] = None,
               severity: Optional[str] = None, target_id: Optional[int] = None,
               changed: Optional[bool] = None, category: Optional[str] = None):
    with session_scope() as s:
        qq = s.query(Page).order_by(Page.crawled_at.desc())
        if q:
            like = f"%{q}%"
            qq = qq.filter(or_(Page.title.ilike(like), Page.url.ilike(like), Page.ai_summary.ilike(like),
                               Page.content.ilike(like)))
        if severity:
            qq = qq.filter(Page.ai_severity == severity)
        if target_id:
            qq = qq.filter(Page.target_id == target_id)
        if changed is not None:
            qq = qq.filter(Page.changed.is_(changed))
        if category:
            qq = qq.filter(Page.ai_category == category)
        return _page(qq, limit, offset, page_dict)


@router.get("/pages/{pid}")
def get_page(pid: int):
    with session_scope() as s:
        p = s.get(Page, pid)
        if not p:
            raise HTTPException(404, "not found")
        d = page_dict(p, content=True)
        seen, inds = set(), []
        for sg in s.query(Sighting).filter_by(page_id=pid).order_by(Sighting.id.desc()).limit(300):
            if sg.indicator_id in seen:
                continue
            seen.add(sg.indicator_id)
            inds.append({**indicator_dict(sg.indicator), "context": sg.context, "source": sg.source})
        d["indicators"] = inds
        d["alerts"] = [alert_dict(a) for a in s.query(Alert).filter_by(page_id=pid)]
        return d


# ---------------------------------------------------------------- indicators
def _indicator_query(s, q, ioc_type, watch_only, tag):
    qq = s.query(Indicator).order_by(Indicator.last_seen.desc())
    if q:
        qq = qq.filter(Indicator.value.ilike(f"%{q}%"))
    if ioc_type:
        qq = qq.filter(Indicator.ioc_type == ioc_type)
    if watch_only:
        qq = qq.filter(Indicator.on_watchlist.is_(True))
    if tag:
        qq = qq.filter(Indicator.tags.ilike(f"%{tag}%"))
    return qq


@router.get("/indicators")
def list_indicators(limit: int = Query(100, le=1000), offset: int = 0, q: Optional[str] = None,
                    ioc_type: Optional[str] = None, watch_only: bool = False, tag: Optional[str] = None):
    with session_scope() as s:
        return _page(_indicator_query(s, q, ioc_type, watch_only, tag), limit, offset, indicator_dict)


@router.get("/indicators/export")
def export_indicators(fmt: Literal["csv", "json", "stix", "misp"] = "csv", q: Optional[str] = None,
                      ioc_type: Optional[str] = None, watch_only: bool = False, tag: Optional[str] = None):
    from .. import exports
    with session_scope() as s:
        rows = _indicator_query(s, q, ioc_type, watch_only, tag).limit(50000).all()
        if fmt == "csv":
            body, mt, ext = exports.indicators_csv(rows), "text/csv", "csv"
        elif fmt == "json":
            body, mt, ext = exports.indicators_json(rows), "application/json", "json"
        elif fmt == "stix":
            body, mt, ext = json.dumps(exports.indicators_stix(rows), indent=2), "application/stix+json", "stix.json"
        else:
            body, mt, ext = json.dumps(exports.indicators_misp(rows), indent=2), "application/json", "misp.json"
    audit("export", f"indicators {fmt} {len(rows)}", actor="api")
    return Response(body, media_type=mt,
                    headers={"Content-Disposition": f'attachment; filename="indicators.{ext}"'})


@router.get("/indicators/{iid}")
def get_indicator(iid: int):
    with session_scope() as s:
        i = s.get(Indicator, iid)
        if not i:
            raise HTTPException(404, "not found")
        d = indicator_dict(i)
        d["sightings"] = [{"page_id": sg.page_id, "run_id": sg.run_id, "context": sg.context,
                           "source": sg.source, "created_at": _iso(sg.created_at),
                           "page_url": sg.page.url if sg.page else None}
                          for sg in s.query(Sighting).filter_by(indicator_id=iid).order_by(Sighting.id.desc()).limit(100)]
        return d


@router.post("/indicators/{iid}/enrich")
def enrich_indicator(iid: int):
    from ..sources.feeds import enrich
    with session_scope() as s:
        i = s.get(Indicator, iid)
        if not i:
            raise HTTPException(404, "not found")
        t, v = i.ioc_type, i.value
    return enrich(t, v)


# ---------------------------------------------------------------- alerts
@router.get("/alerts")
def list_alerts(limit: int = Query(50, le=500), offset: int = 0, status: Optional[str] = None,
                severity: Optional[str] = None, source: Optional[str] = None, q: Optional[str] = None,
                target_id: Optional[int] = None):
    with session_scope() as s:
        qq = s.query(Alert).order_by(Alert.last_seen.desc(), Alert.id.desc())
        if status == "open":
            qq = qq.filter(Alert.status.in_(("new", "acknowledged")))
        elif status:
            qq = qq.filter(Alert.status == status)
        if severity:
            qq = qq.filter(Alert.severity.in_(severity.split(",")))
        if source:
            qq = qq.filter(Alert.source == source)
        if target_id:
            qq = qq.filter(Alert.target_id == target_id)
        if q:
            qq = qq.filter(or_(Alert.title.ilike(f"%{q}%"), Alert.description.ilike(f"%{q}%")))
        return _page(qq, limit, offset, alert_dict)


@router.get("/alerts/{aid}")
def get_alert(aid: int):
    with session_scope() as s:
        a = s.get(Alert, aid)
        if not a:
            raise HTTPException(404, "not found")
        return alert_dict(a)


@router.patch("/alerts/{aid}")
def patch_alert(aid: int, p: AlertPatch):
    with session_scope() as s:
        a = s.get(Alert, aid)
        if not a:
            raise HTTPException(404, "not found")
        old = a.status
        for k, v in p.model_dump(exclude_unset=True).items():
            setattr(a, k, v)
        out = alert_dict(a)
    audit("alert.update", f"{aid} {p.model_dump(exclude_unset=True)}", actor="api")
    if p.status and p.status != old:
        from ..learning.feedback import record_status
        record_status(aid, p.status)
    return out


@router.post("/alerts/bulk")
def bulk_alerts(b: AlertBulk):
    with session_scope() as s:
        n = s.query(Alert).filter(Alert.id.in_(b.ids)).update({Alert.status: b.status}, synchronize_session=False)
    audit("alert.bulk", f"{len(b.ids)} -> {b.status}", actor="api")
    from ..learning.feedback import record_status
    for aid in b.ids[:500]:
        record_status(aid, b.status)
    return {"updated": n}


@router.post("/alerts/{aid}/misp")
def alert_to_misp(aid: int):
    from ..integrations.misp import push_alert
    with session_scope() as s:
        a = s.get(Alert, aid)
        if not a:
            raise HTTPException(404, "not found")
        try:
            res = push_alert(s, a)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"MISP push failed: {e}") from e
    audit("alert.misp", f"{aid} -> {res}", actor="api")
    return res


@router.post("/alerts/{aid}/triage")
def retriage(aid: int):
    from ..ai.base import AIError
    with session_scope() as s:
        a = s.get(Alert, aid)
        if not a:
            raise HTTPException(404, "not found")
        try:
            a.triage = get_router().triage_alert(a.title, a.severity, a.matches or [], a.description or "", [])
        except AIError as e:
            raise HTTPException(503, str(e)) from e
        return alert_dict(a)


# ---------------------------------------------------------------- watchlist
@router.get("/watchlist")
def list_watch():
    with session_scope() as s:
        return {"kinds": list(WATCH_KINDS),
                "items": [watch_dict(w) for w in s.query(WatchItem).order_by(WatchItem.kind, WatchItem.value)]}


@router.post("/watchlist", status_code=201)
def add_watch(w: WatchIn):
    err = validate_watch(w.kind, w.value)
    if err:
        raise HTTPException(422, err)
    with session_scope() as s:
        if s.query(WatchItem).filter_by(kind=w.kind, value=w.value.strip()).first():
            raise HTTPException(409, "already on the watchlist")
        item = WatchItem(kind=w.kind, value=w.value.strip(), severity=w.severity, note=w.note, active=w.active)
        s.add(item)
        s.flush()
        out = watch_dict(item)
    audit("watch.add", f"{w.kind}:{w.value}", actor="api")
    return out


@router.patch("/watchlist/{wid}")
def patch_watch(wid: int, p: WatchPatch):
    with session_scope() as s:
        w = s.get(WatchItem, wid)
        if not w:
            raise HTTPException(404, "not found")
        for k, v in p.model_dump(exclude_unset=True).items():
            setattr(w, k, v)
        return watch_dict(w)


@router.delete("/watchlist/{wid}")
def del_watch(wid: int):
    with session_scope() as s:
        w = s.get(WatchItem, wid)
        if not w:
            raise HTTPException(404, "not found")
        s.delete(w)
    audit("watch.delete", str(wid), actor="api")
    return {"ok": True}


# ---------------------------------------------------------------- tasks
@router.get("/tasks")
def list_tasks(status: Optional[str] = None, limit: int = Query(100, le=500), offset: int = 0):
    with session_scope() as s:
        q = s.query(Task).order_by(Task.id.desc())
        if status:
            q = q.filter(Task.status.in_(status.split(",")))
        return _page(q, limit, offset, task_dict)


@router.post("/tasks", status_code=201)
def create_manual_task(t: TaskIn):
    from ..tasks import _clean, create_task
    c = _clean(t.model_dump(), t.target_id, None)
    if not c:
        raise HTTPException(422, "invalid task payload")
    tid = create_task(c, source="user")
    if not tid:
        raise HTTPException(409, "an identical task already exists")
    return {"id": tid}


@router.post("/tasks/{tid}/approve")
def approve(tid: int):
    from ..tasks import approve_task
    try:
        return approve_task(tid, actor="api")
    except KeyError as e:
        raise HTTPException(404, "not found") from e


@router.post("/tasks/{tid}/reject")
def reject(tid: int):
    from ..tasks import reject_task
    try:
        return reject_task(tid, actor="api")
    except KeyError as e:
        raise HTTPException(404, "not found") from e


# ---------------------------------------------------------------- sources / feeds
@router.get("/sources")
def list_sources():
    from ..sources.runner import source_status
    with session_scope() as s:
        history = [{"id": r.id, "source": r.source, "status": r.status, "started": _iso(r.started_at),
                    "finished": _iso(r.finished_at), "queries": r.queries, "findings": r.findings,
                    "alerts": r.alerts, "error": r.error}
                   for r in s.query(SourceRun).order_by(SourceRun.id.desc()).limit(30)]
    return {"sources": source_status(), "history": history}


@router.post("/sources/{name}/run", status_code=202)
def run_source_now(name: str):
    import threading
    from ..sources.runner import get_source, run_source
    try:
        get_source(name)
    except KeyError as e:
        raise HTTPException(404, "unknown source") from e
    threading.Thread(target=run_source, args=(name,), daemon=True).start()
    return {"queued": name}


@router.post("/feeds/refresh", status_code=202)
def refresh_feeds_now():
    import threading
    from ..sources.feeds import refresh_feeds
    threading.Thread(target=refresh_feeds, daemon=True).start()
    return {"queued": True}
