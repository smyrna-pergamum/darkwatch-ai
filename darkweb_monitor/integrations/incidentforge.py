"""IncidentForge bridge: escalate a darknet finding into an incident case.

DarkWatch AI covers the *outside-in* view (what is leaked / offered about an
organisation); IncidentForge covers incident response and forensics. An
escalation sends one JSON case (schema ``darkwatch.incident/1``) with the
alert, its threat class and risk, the affected organisations, related
threat actors, indicators and the hashed evidence with chain of custody, so
the investigation starts from preserved, verifiable data.

Contract: ``POST {INCIDENTFORGE_URL}{INCIDENTFORGE_INCIDENT_PATH}`` with
``Authorization: Bearer <INCIDENTFORGE_API_KEY>``; a 2xx JSON response with
``id`` (or ``incident_id`` / ``key``) is stored on the alert as ``incident_ref``."""
from __future__ import annotations

import base64
import logging

import requests

from config.settings import settings
from ..storage.models import Alert, Indicator, Sighting, utcnow
from ..storage.models_intel import AlertOrg, Evidence, Organization

logger = logging.getLogger(__name__)
SCHEMA = "darkwatch.incident/1"
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


class IncidentForgeError(RuntimeError):
    pass


def configured() -> bool:
    return bool(settings.INCIDENTFORGE_URL)


def build_payload(s, alert: Alert, actor: str = "system") -> dict:
    from ..intel.actors import actors_for_alert
    from ..intel.evidence import evidence_dict, read_content, EvidenceError

    orgs = [s.get(Organization, oid) for (oid,) in s.query(AlertOrg.org_id).filter_by(alert_id=alert.id)]
    indicators = []
    if alert.page_id:
        q = (s.query(Indicator).join(Sighting, Sighting.indicator_id == Indicator.id)
             .filter(Sighting.page_id == alert.page_id).distinct().limit(200))
        indicators = [{"type": i.ioc_type, "value": i.value, "first_seen": i.first_seen.isoformat() + "Z"
                       if i.first_seen else None, "tags": i.tags} for i in q]
    evidence = []
    for ev in s.query(Evidence).filter_by(alert_id=alert.id).order_by(Evidence.id):
        item = evidence_dict(s, ev, custody=True)
        if settings.INCIDENTFORGE_INCLUDE_EVIDENCE:
            try:
                item["content_b64"] = base64.b64encode(read_content(ev)).decode()
            except EvidenceError as e:
                item["content_error"] = str(e)
        evidence.append(item)
    return {
        "schema": SCHEMA,
        "source": "darkwatch-ai",
        "external_id": f"darkwatch-alert-{alert.id}",
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "priority": PRIORITY.get(alert.severity, "P3"),
        "category": alert.threat_class or "darknet_finding",
        "risk_score": alert.risk_score,
        "risk_factors": alert.risk_factors or [],
        "detected_at": alert.created_at.isoformat() + "Z" if alert.created_at else None,
        "last_seen": alert.last_seen.isoformat() + "Z" if alert.last_seen else None,
        "reference_url": alert.url,
        "detection_source": alert.source,
        "organizations": [{"id": o.id, "name": o.name, "slug": o.slug, "sector": o.sector} for o in orgs if o],
        "matched_assets": [{"kind": m.get("kind"), "value": m.get("value")} for m in (alert.matches or [])
                           if isinstance(m, dict)],
        "threat_actors": [{"id": a.id, "name": a.name, "kind": a.kind, "aliases": a.aliases or []}
                          for a in actors_for_alert(s, alert.id) if a],
        "indicators": indicators,
        "ai_triage": alert.triage or {},
        "evidence": evidence,
        "escalated_by": actor,
        "escalated_at": utcnow().isoformat() + "Z",
    }


def _send(payload: dict, session: requests.Session | None = None) -> str:
    url = settings.INCIDENTFORGE_URL.rstrip("/") + "/" + settings.INCIDENTFORGE_INCIDENT_PATH.lstrip("/")
    headers = {"Content-Type": "application/json", "User-Agent": "darkwatch-ai"}
    if settings.INCIDENTFORGE_API_KEY:
        headers["Authorization"] = f"Bearer {settings.INCIDENTFORGE_API_KEY}"
    http = session or requests.Session()
    try:
        r = http.post(url, json=payload, headers=headers, timeout=30, verify=settings.INCIDENTFORGE_VERIFY_TLS)
    except requests.RequestException as e:
        raise IncidentForgeError(f"IncidentForge unreachable: {e}") from e
    if r.status_code >= 300:
        raise IncidentForgeError(f"IncidentForge HTTP {r.status_code}: {r.text[:200]}")
    try:
        body = r.json() or {}
    except ValueError:
        body = {}
    return str(body.get("id") or body.get("incident_id") or body.get("key") or payload["external_id"])[:128]


def escalate_alert(alert_id: int, actor: str = "system", session: requests.Session | None = None) -> str:
    """Create the case; returns the IncidentForge reference. Raises IncidentForgeError.

    Three phases so that no database transaction (and no SQLite write lock) is
    held during the HTTP call: build the payload, POST it, record the result."""
    from ..intel.evidence import add_custody
    from ..storage.db import session_scope
    if not configured():
        raise IncidentForgeError("INCIDENTFORGE_URL is not configured")
    with session_scope() as s:
        alert = s.get(Alert, alert_id)
        if not alert:
            raise IncidentForgeError("alert not found")
        if alert.incident_ref:
            return alert.incident_ref
        payload = build_payload(s, alert, actor)
    ref = _send(payload, session)
    with session_scope() as s:
        alert = s.get(Alert, alert_id)
        alert.incident_ref = ref
        for ev in s.query(Evidence).filter_by(alert_id=alert_id):
            add_custody(s, ev, "escalated", actor, f"IncidentForge case {ref}")
    return ref
