"""Freeze corrected cases as regression scenarios for the analyst agent."""
from __future__ import annotations

from ..ioc.extractor import mask_credentials
from ..storage.db import session_scope
from ..storage.models import Alert, EvalCase, Page, Sighting


def snapshot(alert_id: int, expected: list[str], note: str = "", name: str = "") -> int:
    with session_scope() as s:
        a = s.get(Alert, alert_id)
        if not a:
            raise KeyError(alert_id)
        existing = s.query(EvalCase).filter_by(source_alert_id=alert_id, active=True).first()
        if existing:
            existing.expected, existing.note = expected, note or existing.note
            return existing.id
        page_title, content, inds = "", "", []
        if a.page_id:
            p = s.get(Page, a.page_id)
            if p:
                page_title, content = p.title, mask_credentials(p.content or "")[:30000]
            seen = set()
            for sg in s.query(Sighting).filter_by(page_id=a.page_id).limit(100):
                i = sg.indicator
                if i.id not in seen:
                    seen.add(i.id)
                    inds.append({"type": i.ioc_type, "value": i.value, "watchlist": i.on_watchlist})
        vals = {str(m.get("value", "")).lower() for m in a.matches or []}
        history = []
        for o in s.query(Alert).filter(Alert.id != a.id).order_by(Alert.id.desc()).limit(300):
            if vals & {str(m.get("value", "")).lower() for m in o.matches or []}:
                history.append({"title": o.title, "status": o.status, "severity": o.severity, "matches": o.matches or []})
            if len(history) >= 5:
                break
        c = EvalCase(name=name or f"case-{alert_id}: {a.title[:120]}", source_alert_id=alert_id,
                     alert={"title": a.title, "severity": a.severity, "source": a.source, "matches": a.matches or [],
                            "description": (a.description or "")[:2000]},
                     page_title=page_title, page_content=content, indicators=inds, history=history,
                     expected=expected, note=note[:2000])
        s.add(c)
        s.flush()
        return c.id


def load_active() -> list[dict]:
    with session_scope() as s:
        return [{"id": c.id, "name": c.name, "alert": c.alert, "page_title": c.page_title,
                 "page_content": c.page_content, "indicators": c.indicators, "history": c.history,
                 "expected": c.expected, "note": c.note} for c in s.query(EvalCase).filter_by(active=True)]
