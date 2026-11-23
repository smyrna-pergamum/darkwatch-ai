"""Create / deduplicate alerts, run AI triage, notify, optional MISP push."""
from __future__ import annotations

import hashlib
import logging

from config.settings import settings
from ..ai.base import AIError
from ..storage.models import SEVERITY_RANK, Alert, utcnow
from .notifier import Notifier, meets_threshold

logger = logging.getLogger(__name__)
notifier = Notifier()


def dedup_key(*parts: str) -> str:
    return hashlib.sha256("|".join(p or "" for p in parts).encode()).hexdigest()[:32]


def raise_alert(s, *, source: str, key: str, title: str, description: str, severity: str,
                url: str = "", matches: list | None = None, iocs: list | None = None,
                page_id: int | None = None, target_id: int | None = None,
                run_id: int | None = None, summary: str = "", router=None) -> tuple[Alert, bool]:
    """Return (alert, created). Re-sightings increase ``occurrences`` and only
    notify again when severity escalates. ``false_positive`` alerts stay quiet;
    ``resolved`` alerts re-open as a new alert (recurrence)."""
    matches = matches or []
    existing = s.query(Alert).filter_by(dedup_key=key).order_by(Alert.id.desc()).first()
    if existing and existing.status in ("new", "acknowledged", "false_positive"):
        existing.occurrences = (existing.occurrences or 1) + 1
        existing.last_seen = utcnow()
        existing.run_id = run_id or existing.run_id
        existing.page_id = page_id or existing.page_id
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing.severity, 0) \
                and existing.status != "false_positive":
            existing.severity = severity
            sent = notifier.notify(f"(escalated) {existing.title}", existing.description,
                                   severity=severity, url=url)
            existing.notified = existing.notified or bool(sent)
        return existing, False

    alert = Alert(source=source, page_id=page_id, target_id=target_id, run_id=run_id, url=url,
                  severity=severity, title=title[:500], description=description[:8000],
                  matches=matches, dedup_key=key)
    s.add(alert)
    s.flush()
    suppress = False
    if router is not None and settings.AI_TRIAGE and meets_threshold(severity) \
            and router.available("triage"):
        try:
            from ..learning.lessons import for_alert, format_for_prompt
            lessons = for_alert({"title": title, "description": description, "matches": matches}, k=3)
            if lessons:
                summary = (summary or description[:1200]) + "\n\n" + format_for_prompt(lessons, 900)
            tri = router.triage_alert(title, severity,
                                      [{"kind": m.get("kind"), "value": m.get("value")} for m in matches],
                                      summary or description[:1500], list(iocs or []))
            alert.triage = tri
            if settings.AI_TRIAGE_SUPPRESS and tri.get("true_positive") is False \
                    and float(tri.get("confidence", 0) or 0) >= 0.7:
                suppress = True
        except AIError as e:
            alert.triage = {"error": str(e)[:200]}
    if not suppress:
        sent = notifier.notify(title, description[:1500], severity=severity,
                               iocs=list(iocs or []), url=url)
        alert.notified, alert.notify_channels = bool(sent), ",".join(sent)
    if settings.MISP_URL and settings.MISP_AUTO_PUSH_SEVERITY and \
            SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(settings.MISP_AUTO_PUSH_SEVERITY, 9):
        try:
            from ..integrations.misp import push_alert
            push_alert(s, alert)
        except Exception as e:  # noqa: BLE001
            logger.warning("MISP auto-push failed: %s", e)
    return alert, True
