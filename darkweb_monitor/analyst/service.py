"""Analyst sessions: start, continue, cancel, approvals, auto-investigation."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from config.settings import settings
from ..harness.errors import HarnessError
from ..harness.llm import Adapter, select_adapter
from ..harness.session import SessionLog
from ..harness.tools import RunContext, ToolCall
from ..storage.db import audit, session_scope
from ..storage.models import SEVERITY_RANK, AgentApproval, AgentSession, Alert, utcnow
from .agent import RulesAdapter, build

logger = logging.getLogger(__name__)

_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="analyst")  # local models: one at a time
_flags: dict[int, threading.Event] = {}
_lock = threading.Lock()
_adapter_override: Adapter | None = None  # tests / evals


def set_adapter(adapter: Adapter | None) -> None:
    global _adapter_override
    _adapter_override = adapter


def current_adapter() -> Adapter:
    if _adapter_override is not None:
        return _adapter_override
    return select_adapter() or RulesAdapter()


def status() -> dict:
    a = current_adapter()
    try:
        window = a.context_window()
    except Exception:  # noqa: BLE001
        window = None
    with session_scope() as s:
        pending = s.query(AgentApproval).filter_by(status="pending").count()
        running = s.query(AgentSession).filter(AgentSession.status.in_(("queued", "running"))).count()
    return {"enabled": settings.ANALYST_ENABLED, "provider": a.name, "model": a.model, "context_window": window,
            "rule_based": isinstance(a, RulesAdapter), "auto_severity": settings.ANALYST_AUTO_SEVERITY,
            "auto_approve": settings.list_of("ANALYST_AUTO_APPROVE"), "ask": settings.list_of("ANALYST_ASK"),
            "pending_approvals": pending, "running": running}


def _approver(ctx: RunContext, reason: str) -> int:
    with session_scope() as s:
        ap = AgentApproval(session_id=ctx.session_id, call_id=ctx.call.id, tool=ctx.tool.name, args=ctx.call.args,
                           permission=ctx.tool.permission, reason=reason)
        s.add(ap)
        s.flush()
        aid = ap.id
    SessionLog(ctx.session_id).append("approval/requested", {"approval_id": aid, "tool": ctx.tool.name,
                                                             "args": ctx.call.args, "reason": reason})
    return aid


def _opening(alert_id: int | None, question: str | None) -> tuple[str, list[int]]:
    """Opening message + ids of human-confirmed lessons included in it."""
    from ..learning.lessons import format_for_prompt, for_alert, retrieve
    if alert_id:
        with session_scope() as s:
            a = s.get(Alert, alert_id)
            if not a:
                raise ValueError("alert not found")
            head = (f"Investigate alert #{a.id} [{a.severity}] from {a.source}: {a.title}\n"
                    f"Status: {a.status}. Seen {a.occurrences}x.")
            ad = {"title": a.title, "description": a.description or "", "matches": a.matches or []}
        lessons = for_alert(ad, k=4)
        text = head + (f"\nAnalyst question: {question}" if question else
                       "\nDetermine whether it is a real threat to the organisation and what to do.")
    else:
        lessons = retrieve(question or "", k=3)
        text = question or "Review the current open alerts."
    block = format_for_prompt(lessons)
    return (text + ("\n\n" + block if block else "")), [lesson["id"] for _, lesson in lessons]


def start(alert_id: int | None = None, question: str | None = None, trigger: str = "manual",
          agent: str = "analyst") -> int:
    if agent == "assistant":
        return _start_assistant(question or "", trigger)
    if not settings.ANALYST_ENABLED:
        raise ValueError("analyst agent is disabled (ANALYST_ENABLED=false)")
    if alert_id:
        with session_scope() as s:
            active = s.query(AgentSession).filter(AgentSession.subject_type == "alert",
                                                  AgentSession.subject_id == alert_id,
                                                  AgentSession.status.in_(("queued", "running"))).first()
            if active:
                return active.id
    text, lesson_ids = _opening(alert_id, question)
    log = SessionLog.create("analyst", title=text.splitlines()[0][:200], subject_type="alert" if alert_id else "free",
                            subject_id=alert_id, trigger=trigger)
    if lesson_ids:
        from ..learning.lessons import mark_used
        log.append("lessons/used", {"ids": lesson_ids})
        mark_used(lesson_ids)
    if alert_id:
        with session_scope() as s:
            s.get(Alert, alert_id).analyst_session_id = log.session_id
    _submit(log.session_id, text, trigger)
    audit("analyst.start", f"session {log.session_id} alert={alert_id} trigger={trigger}", actor=trigger)
    return log.session_id


def _start_assistant(question: str, trigger: str) -> int:
    question = question.strip()
    if not question:
        raise ValueError("question required")
    log = SessionLog.create("assistant", title=question.splitlines()[0][:200], subject_type="help", trigger=trigger)
    _submit(log.session_id, assistant_opening(question), trigger)
    return log.session_id


def assistant_opening(question: str) -> str:
    """Question + the guide sections and setup state it needs, so even a small
    model can answer directly (tools stay available for follow-ups)."""
    from ..assistant import kb
    from ..assistant.tools import app_status
    parts = [question, "", "[Relevant guide sections]"]
    parts += [f"- {t['title']}: {t['body']}" for t in kb.search(question, k=2)]
    try:
        st = app_status({}, None)
        steps = "; ".join(f"{'done' if x['done'] else ('NEXT' if x['next'] else 'todo')}: {x['title']} ({x['detail']})"
                          for x in st["setup_checklist"])
        parts += ["", "[Current setup state, in order]", steps]
    except Exception:  # noqa: BLE001
        pass
    parts += ["", "Answer the question now in the user's language using this information. "
                  "Call a tool only if something is missing."]
    return "\n".join(parts)


def send(session_id: int, text: str) -> None:
    with session_scope() as s:
        row = s.get(AgentSession, session_id)
        if not row:
            raise KeyError(session_id)
        if row.status in ("queued", "running"):
            raise ValueError("the agent is still working on this session")
    _submit(session_id, text, "user")


def _submit(session_id: int, text: str, trigger: str) -> None:
    flag = threading.Event()
    with _lock:
        _flags[session_id] = flag
    SessionLog(session_id).update(status="queued", error="")
    _pool.submit(_run, session_id, text, trigger, flag)


def run_sync(session_id: int, text: str, trigger: str = "user") -> None:
    """Run one turn in the caller's thread (CLI / evals / tests)."""
    _run(session_id, text, trigger, threading.Event())


def _run(session_id: int, text: str, trigger: str, flag: threading.Event) -> None:
    log = SessionLog(session_id)
    try:
        if flag.is_set():
            log.update(status="cancelled")
            return
        adapter = current_adapter()
        agent_id = (log.row() or {}).get("agent") or "analyst"
        loop, _ = build(adapter, agent_id=agent_id if agent_id in ("analyst", "assistant") else "analyst",
                        approver=_approver)
        state = {"provider": f"{adapter.name}/{adapter.model}" if adapter.model else adapter.name,
                 "page_chunk_chars": max(1200, int(adapter.context_window() * 3.2 * 0.25))}
        outcome = loop.run_turn(log, text, trigger, flag.is_set, state)
        row = log.row()
        with session_scope() as s:
            pending = s.query(AgentApproval).filter_by(session_id=session_id, status="pending").count()
        if outcome.reason == "cancelled":
            st = "cancelled"
        elif outcome.reason == "error":
            st = "failed"
        elif pending:
            st = "waiting_approval"
        else:
            st = "done" if row.get("report") else "idle"
        log.update(status=st, error=outcome.error[:2000])
    except Exception as e:  # noqa: BLE001
        logger.exception("analyst session %s crashed", session_id)
        log.update(status="failed", error=f"{type(e).__name__}: {e}"[:2000])
    finally:
        with _lock:
            _flags.pop(session_id, None)


def cancel(session_id: int) -> bool:
    with _lock:
        f = _flags.get(session_id)
    if f:
        f.set()
    return bool(f)


def decide(approval_id: int, approve: bool, actor: str = "user") -> dict:
    """Execute (or reject) a queued tool call. The body runs with the exact
    arguments the agent proposed; the outcome is logged into the session so
    the agent sees it on its next turn."""
    with session_scope() as s:
        ap = s.get(AgentApproval, approval_id)
        if not ap:
            raise KeyError(approval_id)
        if ap.status != "pending":
            return {"id": ap.id, "status": ap.status}
        sid, tool_name, args = ap.session_id, ap.tool, dict(ap.args or {})
    status, result, summary = "rejected", None, "rejected by a human - do not retry it"
    if approve:
        _, reg = build(RulesAdapter())
        tool = reg.get(tool_name)
        try:
            result = tool.execute(args, RunContext(sid, "analyst", ToolCall(f"approval-{approval_id}", tool_name, args),
                                                   tool, {}))
            status, summary = "approved", f"executed: {result}"
        except HarnessError as e:
            status, result, summary = "failed", e.as_dict(), f"failed: {e}"
        except Exception as e:  # noqa: BLE001
            status, result, summary = "failed", {"error": str(e)}, f"failed: {e}"
    with session_scope() as s:
        ap = s.get(AgentApproval, approval_id)
        ap.status, ap.result, ap.decided_at, ap.decided_by = status, result, utcnow(), actor
        s.flush()
        left = s.query(AgentApproval).filter_by(session_id=sid, status="pending").count()
        row = s.get(AgentSession, sid)
        if not left and row.status == "waiting_approval":
            row.status = "done" if row.report else "idle"
    SessionLog(sid).append("approval/resolved", {"approval_id": approval_id, "tool": tool_name, "args": args,
                                                 "status": status, "summary": str(summary)[:500], "by": actor})
    audit(f"analyst.approval.{status}", f"#{approval_id} {tool_name} {args}", actor=actor)
    return {"id": approval_id, "status": status, "result": result}


def recover() -> int:
    with session_scope() as s:
        rows = s.query(AgentSession).filter(AgentSession.status.in_(("queued", "running"))).all()
        for r in rows:
            r.status, r.error = "failed", "interrupted (process restarted)"
        return len(rows)


def auto_investigate() -> list[int]:
    """Scheduler job: investigate new alerts at/above ANALYST_AUTO_SEVERITY."""
    sev = settings.ANALYST_AUTO_SEVERITY
    if not settings.ANALYST_ENABLED or sev not in SEVERITY_RANK:
        return []
    now = utcnow()
    with session_scope() as s:
        recent = s.query(AgentSession).filter(AgentSession.trigger == "auto",
                                              AgentSession.created_at >= now - timedelta(hours=1)).count()
        room = max(0, settings.ANALYST_AUTO_MAX_PER_HOUR - recent)
        cands = [a.id for a in s.query(Alert).filter(Alert.status == "new", Alert.analyst_session_id.is_(None),
                                                     Alert.created_at >= now - timedelta(hours=48))
                 .order_by(Alert.id.desc()).limit(50)
                 if SEVERITY_RANK.get(a.severity, 0) >= SEVERITY_RANK[sev]][:room]
    started = []
    for aid in cands:
        try:
            started.append(start(aid, trigger="auto"))
        except Exception as e:  # noqa: BLE001
            logger.warning("auto-investigation of alert %s failed to start: %s", aid, e)
    return started
