"""Record human feedback and turn it into lessons / regression cases."""
from __future__ import annotations

from ..storage.db import audit, session_scope
from ..storage.models import AgentEvent, Alert, Feedback, Lesson, Page

LABELS = ("true_positive", "false_positive", "benign", "needs_more_info")
STATUS_LABEL = {"false_positive": "false_positive", "resolved": "true_positive", "acknowledged": "true_positive"}


def _ai_verdict(a: Alert) -> tuple[str, int | None, str]:
    an = (a.triage or {}).get("analyst") or {}
    if an:
        return an.get("verdict", ""), an.get("session_id"), ""
    tri = a.triage or {}
    if "true_positive" in tri:
        return ("true_positive" if tri.get("true_positive") else "false_positive"), None, "triage"
    return "", None, ""


def _lessons_used(session_id: int | None) -> list[int]:
    if not session_id:
        return []
    with session_scope() as s:
        ev = s.query(AgentEvent).filter_by(session_id=session_id, type="lessons/used").all()
        return sorted({i for e in ev for i in (e.payload or {}).get("ids", [])})


def record(alert_id: int, *, agree: bool | None = None, label: str = "", severity: str = "", comment: str = "",
           create_lesson: bool = False, lesson_title: str = "", lesson_terms: list[str] | None = None,
           add_to_eval: bool | None = None, actor: str = "user", source: str = "explicit") -> dict:
    with session_scope() as s:
        a = s.get(Alert, alert_id)
        if not a:
            raise KeyError(alert_id)
        ai_v, sid, _ = _ai_verdict(a)
        if not label and agree is True:
            label = ai_v
        if label and label not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")
        if agree is None and label and ai_v:
            agree = label == ai_v
        fb = Feedback(alert_id=alert_id, session_id=sid, source=source, ai_verdict=ai_v, agree=agree, label=label,
                      severity=severity, comment=comment[:4000], actor=actor,
                      provider=((a.triage or {}).get("analyst") or {}).get("provider", ""))
        s.add(fb)
        s.flush()
        fid = fb.id
        title, matches, category = a.title, a.matches or [], ""
        if a.page_id:
            p = s.get(Page, a.page_id)
            category = p.ai_category if p else ""
    # lessons that were shown to the AI for this case get credit / blame
    used = _lessons_used(sid)
    if used and agree is not None and source == "explicit":
        with session_scope() as s:
            for lesson in s.query(Lesson).filter(Lesson.id.in_(used)):
                if agree:
                    lesson.helpful = (lesson.helpful or 0) + 1
                else:
                    lesson.unhelpful = (lesson.unhelpful or 0) + 1
    out = {"id": fid, "label": label, "agree": agree, "ai_verdict": ai_v}
    if create_lesson and comment.strip():
        with session_scope() as s:
            ctx = "; ".join((m.get("context") or "")[:160] for m in matches[:2])
            lesson = Lesson(title=(lesson_title or f"{label or 'decision'}: {title}")[:300], text=comment.strip()[:2000],
                            verdict=label, severity=severity, category=category, example=ctx[:500],
                            terms=lesson_terms if lesson_terms is not None else [m.get("value") for m in matches if m.get("value")][:8],
                            source_alert_id=alert_id, source="feedback", status="active")
            s.add(lesson)
            s.flush()
            out["lesson_id"] = lesson.id
    if add_to_eval is None:
        add_to_eval = source == "explicit" and agree is False and bool(label)
    if add_to_eval and label:
        from .evalcases import snapshot
        out["eval_case_id"] = snapshot(alert_id, [label] + (["needs_more_info"] if label != "needs_more_info" else []),
                                       note=comment)
    audit("feedback", f"alert {alert_id} agree={agree} label={label} lesson={out.get('lesson_id')}", actor=actor)
    return out


def record_status(alert_id: int, status: str, actor: str = "user") -> None:
    """Implicit weak label from an analyst changing an alert's status."""
    label = STATUS_LABEL.get(status)
    if not label:
        return
    try:
        record(alert_id, label=label, actor=actor, source="status", add_to_eval=False)
    except (KeyError, ValueError):
        pass


def stats() -> dict:
    with session_scope() as s:
        rows = s.query(Feedback).filter(Feedback.source == "explicit").all()
        judged = [r for r in rows if r.agree is not None]
        by_provider: dict = {}
        for r in judged:
            d = by_provider.setdefault(r.provider or "unknown", {"agree": 0, "total": 0})
            d["total"] += 1
            d["agree"] += int(bool(r.agree))
        labels: dict = {}
        for r in s.query(Feedback).all():
            if r.label:
                labels[r.label] = labels.get(r.label, 0) + 1
        return {"explicit": len(rows), "judged": len(judged),
                "agreement": round(sum(1 for r in judged if r.agree) / len(judged), 3) if judged else None,
                "by_provider": by_provider, "labels": labels,
                "recent": [{"id": r.id, "alert_id": r.alert_id, "agree": r.agree, "label": r.label,
                            "ai_verdict": r.ai_verdict, "comment": r.comment[:300], "source": r.source,
                            "created_at": r.created_at.isoformat() + "Z"}
                           for r in s.query(Feedback).order_by(Feedback.id.desc()).limit(30)]}
