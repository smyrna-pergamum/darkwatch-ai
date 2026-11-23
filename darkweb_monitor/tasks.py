"""Automatic follow-up tasks: planning (AI + heuristics), approval, execution.

Safety rule: tasks that widen the monitoring surface (``add_target``) are
NEVER auto-approved - a human must approve them in the dashboard.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from config.settings import settings
from .ai.base import AIError
from .crawler.parsers import is_onion, normalize_url
from .storage.db import audit, session_scope
from .storage.models import Target, Task, WatchItem, utcnow
from .watchlist import validate as validate_watch

logger = logging.getLogger(__name__)

KINDS = ("recrawl", "add_target", "add_watch", "review")
NEVER_AUTO = {"add_target"}


def _clean(task: dict, target_id: int | None, run_id: int | None) -> dict | None:
    kind = str(task.get("kind", "")).strip()
    if kind not in KINDS:
        return None
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    if kind == "recrawl":
        try:
            mins = int(payload.get("in_minutes", 60))
        except (TypeError, ValueError):
            mins = 60
        payload = {"in_minutes": max(15, min(mins, 7 * 24 * 60))}
        if not target_id:
            return None
    elif kind == "add_target":
        url = str(payload.get("url", "")).strip()
        if not url or not is_onion(url):
            return None
        mode = payload.get("mode") if payload.get("mode") in ("standard", "smart", "agent") else "smart"
        payload = {"url": normalize_url(url), "label": str(payload.get("label", ""))[:120],
                   "mode": mode, "goal": str(payload.get("goal", ""))[:500]}
    elif kind == "add_watch":
        k = str(payload.get("kind", "keyword"))
        v = str(payload.get("value", "")).strip()
        if validate_watch(k, v):
            return None
        sev = payload.get("severity") if payload.get("severity") in ("low", "medium", "high", "critical") else "medium"
        payload = {"kind": k, "value": v[:200], "severity": sev}
    elif kind == "review":
        payload = {"page_url": str(payload.get("page_url", ""))[:1024]}
        if not payload["page_url"]:
            return None
    prio = task.get("priority") if task.get("priority") in ("low", "medium", "high") else "medium"
    return {"kind": kind, "title": str(task.get("title") or kind)[:300],
            "reason": str(task.get("reason") or "")[:1000], "payload": payload,
            "priority": prio, "target_id": target_id, "run_id": run_id}


def create_task(t: dict, source: str = "ai") -> int | None:
    """Insert a task unless an identical open one exists. Returns id or None."""
    auto = set(settings.list_of("AUTO_APPROVE_TASKS")) - NEVER_AUTO
    with session_scope() as s:
        open_same = s.query(Task).filter(Task.kind == t["kind"], Task.status.in_(("proposed", "approved")))
        for o in open_same:
            if o.payload == t["payload"] and o.target_id == t.get("target_id"):
                return None
        if t["kind"] == "add_target" and s.query(Target).filter_by(url=t["payload"]["url"]).first():
            return None
        if t["kind"] == "add_watch" and s.query(WatchItem).filter_by(
                kind=t["payload"]["kind"], value=t["payload"]["value"]).first():
            return None
        task = Task(source=source, status="proposed", **t)
        s.add(task)
        s.flush()
        tid = task.id
    if t["kind"] in auto and source in ("ai", "rule"):
        approve_task(tid, actor="auto")
    return tid


def heuristic_plan(ctx: dict) -> list[dict]:
    tasks = []
    sevs = [a.get("severity") for a in ctx.get("alerts", [])]
    if ctx.get("target_id") and any(s in ("high", "critical") for s in sevs):
        tasks.append({"kind": "recrawl", "title": "Re-check target soon (high-severity hit)",
                      "reason": "High/critical alerts in last run - watch for follow-up posts.",
                      "priority": "high", "payload": {"in_minutes": 60}})
    for a in ctx.get("alerts", []):
        if a.get("severity") == "critical" and a.get("url"):
            tasks.append({"kind": "review", "title": f"Analyst review: {a.get('title', '')[:120]}",
                          "reason": "Critical alert", "priority": "high",
                          "payload": {"page_url": a["url"]}})
    for host_url in ctx.get("discovered_from_hits", [])[:3]:
        tasks.append({"kind": "add_target", "title": f"Monitor linked onion {host_url[:60]}",
                      "reason": "Linked from a page that matched the watchlist.",
                      "priority": "medium", "payload": {"url": host_url, "mode": "smart"}})
    return tasks


def plan_after_run(router, ctx: dict, max_tasks: int = 6) -> list[int]:
    """Create follow-up tasks for a finished run. Returns created task ids."""
    raw: list[dict] = []
    source = "rule"
    if settings.AI_TASK_PLANNER and router is not None and router.available("planner"):
        try:
            raw = router.plan_tasks(
                target=ctx.get("start_url"), mode=ctx.get("mode"), schedule=ctx.get("schedule") or "manual",
                run_summary=(ctx.get("run_summary") or {}).get("summary", "")[:1500],
                changed="\n".join(ctx.get("changed_pages", [])[:15]) or "(none)",
                alerts="\n".join(f"[{a.get('severity')}] {a.get('title')}" for a in ctx.get("alerts", [])[:15]) or "(none)",
                discovered=", ".join(ctx.get("discovered", [])[:20]) or "(none)",
                watch=", ".join(ctx.get("watch", [])[:40]) or "(none)", max_tasks=max_tasks)
            source = "ai"
        except AIError as e:
            logger.info("planner AI unavailable, using rules: %s", e)
    if not raw:
        raw = heuristic_plan(ctx)
        source = "rule"
    ids = []
    for t in raw[:max_tasks]:
        c = _clean(t, ctx.get("target_id"), ctx.get("run_id"))
        if c:
            tid = create_task(c, source=source)
            if tid:
                ids.append(tid)
    return ids


def approve_task(task_id: int, actor: str = "user") -> dict:
    with session_scope() as s:
        t = s.get(Task, task_id)
        if not t:
            raise KeyError(task_id)
        if t.status not in ("proposed",):
            return {"id": t.id, "status": t.status}
        p = t.payload or {}
        t.updated_at = utcnow()
        if t.kind == "recrawl":
            t.status = "approved"
            t.due_at = utcnow() + timedelta(minutes=int(p.get("in_minutes", 60)))
        elif t.kind == "add_target":
            if not s.query(Target).filter_by(url=p["url"]).first():
                s.add(Target(url=p["url"], label=p.get("label") or "AI suggested", source="ai",
                             crawl_mode=p.get("mode", "smart"), agent_goal=p.get("goal", ""),
                             schedule_interval_min=settings.DEFAULT_INTERVAL_MIN))
            t.status, t.result = "done", "target added"
        elif t.kind == "add_watch":
            if not s.query(WatchItem).filter_by(kind=p["kind"], value=p["value"]).first():
                s.add(WatchItem(kind=p["kind"], value=p["value"], severity=p.get("severity", "medium"),
                                source="ai", note=t.reason[:500]))
            t.status, t.result = "done", "watch term added"
        else:  # review
            t.status, t.result = "done", "acknowledged by analyst"
        out = {"id": t.id, "status": t.status, "kind": t.kind}
    audit("task.approve", f"task {task_id} {out['kind']}", actor=actor)
    if out["kind"] == "add_target":
        try:
            from .scheduler.jobs import sync_jobs
            sync_jobs()
        except Exception:  # noqa: BLE001
            pass
    return out


def reject_task(task_id: int, actor: str = "user") -> dict:
    with session_scope() as s:
        t = s.get(Task, task_id)
        if not t:
            raise KeyError(task_id)
        if t.status in ("proposed", "approved"):
            t.status = "rejected"
        out = {"id": t.id, "status": t.status}
    audit("task.reject", f"task {task_id}", actor=actor)
    return out


def run_due_tasks(submit) -> int:
    """Execute approved recrawl tasks whose time has come. ``submit`` enqueues a run."""
    now = utcnow()
    with session_scope() as s:
        due = s.query(Task).filter(Task.status == "approved", Task.kind == "recrawl",
                                   Task.due_at <= now).all()
        jobs = [(t.id, t.target_id) for t in due]
    n = 0
    for tid, target_id in jobs:
        try:
            run_id = submit(target_id=target_id, trigger="task")
            status, result = "done", f"run {run_id}"
            n += 1
        except Exception as e:  # noqa: BLE001
            status, result = "failed", str(e)[:500]
        with session_scope() as s:
            t = s.get(Task, tid)
            t.status, t.result, t.updated_at = status, result, utcnow()
    return n
