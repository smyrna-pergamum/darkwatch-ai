"""Alert enrichment hook: runs inside the alert's DB session after an alert is
created or re-sighted. Each step runs in a savepoint - a failing step (e.g. a
unique-constraint race between two crawls) is rolled back on its own and never
breaks alerting. Network calls (IncidentForge) run after the commit."""
from __future__ import annotations

import logging
import threading

from sqlalchemy import event

from config.settings import settings
from ..storage.models import SEVERITY_RANK, Alert

logger = logging.getLogger(__name__)


def _meets(severity: str, threshold: str) -> bool:
    return bool(threshold) and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(threshold, 99)


def _step(name: str, fn, *a, session=None, **k):
    try:
        if session is None:
            return fn(*a, **k)
        with session.begin_nested():
            return fn(*a, **k)
    except Exception:  # noqa: BLE001
        logger.exception("intel enrichment step %s failed", name)
        return None


def _escalate_later(s, alert_id: int) -> None:
    """Queue an IncidentForge escalation to run once this session commits."""
    pending = s.info.setdefault("dw_escalate", set())
    pending.add(alert_id)
    if not s.info.get("dw_escalate_hook"):
        s.info["dw_escalate_hook"] = True
        event.listen(s, "after_commit", _after_commit, once=True)


def _after_commit(session) -> None:
    ids = sorted(session.info.pop("dw_escalate", set()))
    session.info.pop("dw_escalate_hook", None)
    if ids:
        threading.Thread(target=_run_escalations, args=(ids,), name="incidentforge", daemon=True).start()


def _run_escalations(ids: list[int]) -> None:
    from ..integrations.incidentforge import escalate_alert
    for aid in ids:
        _step("incidentforge", escalate_alert, aid, "auto")


def on_alert(s, alert: Alert, created: bool, context: dict | None = None) -> None:
    from .actors import actors_for_alert, ingest_ransomware_alert
    from .classify import classify
    from .orgs import link_alert
    from .risk import alert_risk, compute_org_risk

    ctx = context or {}
    if created or not alert.threat_class:
        text = ctx.get("text") or f"{alert.title}\n{alert.description}"
        c = _step("classify", classify, text, source=alert.source, ai_category=ctx.get("ai_category", ""),
                  ioc_types=ctx.get("ioc_types"))
        if c:
            alert.threat_class = c.threat_class
            tri = dict(alert.triage or {})
            tri["classification"] = c.as_dict()
            alert.triage = tri
    org_ids = _step("link_orgs", link_alert, s, alert, session=s) or set()
    if settings.ACTOR_PROFILING and alert.source == "ransomware":
        _step("ransomware_actor", ingest_ransomware_alert, s, alert, session=s)
    linked = _step("actors", actors_for_alert, s, alert.id) or []
    r = _step("risk", alert_risk, alert, known_actor=bool(linked))
    if r:
        alert.risk_score, alert.risk_factors = r
    _refresh_actor_profiles(linked)
    # alerts the AI triage suppressed as likely false positives are not preserved or escalated
    act = created and not ctx.get("suppressed")
    if act and settings.EVIDENCE_ENABLED and _meets(alert.severity, settings.EVIDENCE_AUTO_SEVERITY):
        from .evidence import capture_for_alert
        _step("evidence", capture_for_alert, s, alert, "auto", "captured automatically on alert", session=s)
    if act and _meets(alert.severity, settings.INCIDENTFORGE_AUTO_SEVERITY):
        from ..integrations.incidentforge import configured
        if configured():
            _escalate_later(s, alert.id)
    for oid in org_ids:
        _step("org_risk", compute_org_risk, s, oid, session=s)


def after_actor_link(s, alert: Alert) -> None:
    """Re-score once forum authors were attributed to an alert (pipeline)."""
    from .actors import actors_for_alert
    from .risk import alert_risk, compute_org_risk
    from ..storage.models_intel import AlertOrg
    r = _step("risk", alert_risk, alert, known_actor=True)
    if r:
        alert.risk_score, alert.risk_factors = r
    _refresh_actor_profiles(_step("actors", actors_for_alert, s, alert.id) or [])
    for (oid,) in s.query(AlertOrg.org_id).filter_by(alert_id=alert.id).all():
        _step("org_risk", compute_org_risk, s, oid, session=s)


def _refresh_actor_profiles(actors) -> None:
    from .actors import build_profile
    from sqlalchemy.orm import object_session
    for a in actors:
        if a is not None:
            sess = object_session(a)
            _step("actor_profile", build_profile, sess, a, session=sess)
