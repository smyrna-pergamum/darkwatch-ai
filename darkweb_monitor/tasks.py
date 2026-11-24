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

KINDS = ("recrawl", "add_target", "add_watch", "review", "mission")
NEVER_AUTO = {"add_target", "mission"}
MISSION_EVERY = {"once": 0, "hourly": 60, "6h": 360, "12h": 720, "daily": 1440, "weekly": 10080}


def mission_interval(v) -> int:
    """'daily' / '6h' / 90 -> minutes (0 = once). Recurring missions run at most hourly."""
    if isinstance(v, str):
        t = v.strip().lower()
        if t in MISSION_EVERY:
            return MISSION_EVERY[t]
        if t.endswith("h") and t[:-1].isdigit():
            v = int(t[:-1]) * 60
        elif t.endswith("d") and t[:-1].isdigit():
            v = int(t[:-1]) * 1440
        elif t.isdigit():
            v = int(t)
        else:
            return 0
    try:
        v = int(v or 0)
    except (TypeError, ValueError):
        return 0
    return 0 if v <= 0 else max(60, min(v, 30 * 1440))


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
    elif kind == "mission":
        instr = str(payload.get("instruction", "")).strip()
        if len(instr) < 5:
            return None
        payload = {"instruction": instr[:2000], "interval_min": mission_interval(payload.get("interval_min", 0))}
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
            op = o.payload or {}
            if t["kind"] == "mission":
                op = {k: op.get(k) for k in ("instruction", "interval_min")}
            if op == t["payload"] and o.target_id == t.get("target_id"):
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
        elif t.kind == "mission":
            t.status, t.due_at, t.result = "approved", utcnow(), "approved - starting"
        else:  # review
            t.status, t.result = "done", "acknowledged by analyst"
        out = {"id": t.id, "status": t.status, "kind": t.kind}
    audit("task.approve", f"task {task_id} {out['kind']}", actor=actor)
    if out["kind"] == "mission":
        out.update(start_mission(task_id))
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


# ------------------------------------------------------------------ missions
def activate_mission(task_id: int, run_now: bool = True, approved: bool = True) -> dict:
    """User-created missions are approved at once; ``run_now`` starts the first run."""
    if not approved:
        return {"status": "proposed", "message": "Mission proposed - approve it in AI Tasks."}
    with session_scope() as s:
        t = s.get(Task, task_id)
        every = (t.payload or {}).get("interval_min", 0)
        t.status = "approved"
        t.due_at = utcnow() if run_now else utcnow() + timedelta(minutes=every or 0)
        t.updated_at = utcnow()
    audit("mission.create", f"task {task_id} every={every}min run_now={run_now}", actor="user")
    if run_now:
        return {"status": "approved", **start_mission(task_id)}
    return {"status": "approved", "every_min": every,
            "message": f"Mission scheduled every {every} min." if every else "Mission saved."}


def start_mission(task_id: int) -> dict:
    """Start one run of a mission as an operator-agent session."""
    from .analyst.service import start
    with session_scope() as s:
        t = s.get(Task, task_id)
        if not t or t.kind != "mission" or t.status != "approved":
            return {"message": "mission is not active"}
        p = dict(t.payload or {})
        instruction, every = p.get("instruction", ""), int(p.get("interval_min") or 0)
    try:
        sid = start(question=instruction, trigger="mission", agent="operator", mission_id=task_id)
        status, result = ("approved" if every else "done"), f"run started: session #{sid}"
    except Exception as e:  # noqa: BLE001
        sid, status, result = None, ("approved" if every else "failed"), f"could not start: {e}"[:500]
    with session_scope() as s:
        t = s.get(Task, task_id)
        p = dict(t.payload or {})
        if sid:
            p["last_session_id"] = sid
            p["runs"] = int(p.get("runs", 0)) + 1
        t.payload = p
        t.status, t.result, t.updated_at = status, result, utcnow()
        t.due_at = utcnow() + timedelta(minutes=every) if every else None
    return {"session_id": sid, "message": result}


def run_due_missions() -> int:
    now = utcnow()
    with session_scope() as s:
        ids = [t.id for t in s.query(Task).filter(Task.status == "approved", Task.kind == "mission",
                                                  Task.due_at <= now)]
    for tid in ids:
        start_mission(tid)
    return len(ids)


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
    try:
        n += run_due_missions()
    except Exception:  # noqa: BLE001
        logger.exception("mission scheduling failed")
    return n
