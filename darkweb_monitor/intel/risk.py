"""Explainable risk scoring for alerts and organisations (0-100).

Alert risk  = severity base + threat-class weight + asset type + AI triage
              + recurrence + known threat actor  (every term is reported).
Org risk    = worst open alert (risk x decay) plus the remaining headroom scaled
              by 1 - prod(1 - 0.5 * c_j) over the other alerts. The decay halves
              an alert's weight every RISK_HALF_LIFE_DAYS since it was last seen.
              One critical finding sets the floor; more findings push it up with
              diminishing returns instead of saturating at 100."""
from __future__ import annotations

import math
from datetime import timedelta

from config.settings import settings
from ..storage.models import Alert, Indicator, WatchItem, utcnow
from ..storage.models_intel import AlertOrg, Organization, OrgAsset
from .classify import class_weight

SEVERITY_BASE = {"low": 10, "medium": 30, "high": 55, "critical": 75}
ASSET_BONUS = {"email": 6, "domain": 5, "ip": 5, "crypto": 4, "brand": 3, "keyword": 1, "regex": 1}
OPEN_STATUSES = ("new", "acknowledged")


def level_for(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def alert_risk(alert: Alert, *, threat_class: str = "", known_actor: bool = False) -> tuple[float, list[dict]]:
    """Return (score, factors) for one alert."""
    if alert.status == "false_positive":
        return 0.0, [{"factor": "marked false positive", "points": 0}]
    factors: list[dict] = []

    def add(label: str, pts: float) -> None:
        if pts:
            factors.append({"factor": label, "points": round(pts, 1)})

    add(f"severity {alert.severity}", SEVERITY_BASE.get(alert.severity or "medium", 30))
    tc = threat_class or alert.threat_class or ""
    if tc:
        add(f"threat class {tc}", class_weight(tc) / 2)
    kinds = {m.get("kind") for m in (alert.matches or []) if isinstance(m, dict)}
    if kinds:
        best = max(kinds, key=lambda k: ASSET_BONUS.get(k, 0))
        add(f"matched {best} asset", ASSET_BONUS.get(best, 0))
    tri = alert.triage or {}
    try:
        conf = float(tri.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        conf = 0.0
    if tri.get("true_positive") is True and conf >= 0.7:
        add("AI triage: likely true positive", 8)
    elif tri.get("true_positive") is False and conf >= 0.7:
        add("AI triage: likely false positive", -25)
    occ = alert.occurrences or 1
    if occ > 1:
        add(f"seen {occ} times", min(8.0, 3 * math.log2(occ)))
    if known_actor:
        add("linked to a known threat actor", 6)
    score = max(0.0, min(100.0, sum(f["points"] for f in factors)))
    return round(score, 1), factors


def _decay(alert: Alert, now) -> float:
    seen = alert.last_seen or alert.created_at or now
    age = max(0.0, (now - seen).total_seconds() / 86400)
    hl = max(0.5, settings.RISK_HALF_LIFE_DAYS)
    return 0.5 ** (age / hl)


def org_domains(s, org_id: int) -> list[str]:
    rows = (s.query(WatchItem.value).join(OrgAsset, OrgAsset.watch_id == WatchItem.id)
            .filter(OrgAsset.org_id == org_id, WatchItem.kind == "domain").all())
    return [r[0].lower().lstrip("@.") for r in rows]


def exposed_credentials(s, org_id: int, limit: int = 500) -> list[Indicator]:
    """Credential indicators (``email:masked#fp``) whose e-mail is at an org domain."""
    from .orgs import like_escape
    out: list[Indicator] = []
    for d in org_domains(s, org_id):
        e = like_escape(d)
        out += (s.query(Indicator).filter(Indicator.ioc_type == "credential",
                                          Indicator.value.like(f"%@{e}:%", escape="\\")).limit(limit).all())
        out += (s.query(Indicator).filter(Indicator.ioc_type == "credential",
                                          Indicator.value.like(f"%.{e}:%", escape="\\")).limit(limit).all())
    return out[:limit]


def compute_org_risk(s, org_id: int, *, save: bool = True) -> dict:
    s.flush()  # sessions run with autoflush off - make pending links visible
    now = utcnow()
    since = now - timedelta(days=max(1, settings.RISK_WINDOW_DAYS))
    alerts = (s.query(Alert).join(AlertOrg, AlertOrg.alert_id == Alert.id)
              .filter(AlertOrg.org_id == org_id, Alert.status.in_(OPEN_STATUSES), Alert.last_seen >= since).all())
    contribs = []
    classes: dict[str, int] = {}
    for a in alerts:
        r = a.risk_score if a.risk_score else alert_risk(a)[0]
        contribs.append(((r / 100.0) * _decay(a, now), a))
        if a.threat_class:
            classes[a.threat_class] = classes.get(a.threat_class, 0) + 1
    contribs.sort(key=lambda x: x[0], reverse=True)
    score = 0.0
    if contribs:
        top = contribs[0][0]
        remaining = 1.0
        for c, _ in contribs[1:]:
            remaining *= 1 - 0.5 * min(0.99, c)
        score = round(100 * (top + (1 - top) * (1 - remaining)), 1)
    creds = exposed_credentials(s, org_id)
    factors = [{"factor": f"alert #{a.id}: {a.title[:90]}", "points": round(100 * c, 1),
                "alert_id": a.id, "threat_class": a.threat_class} for c, a in contribs[:6]]
    if creds:
        bump = min(15.0, 3.0 * math.log2(1 + len(creds)))
        score = round(min(100.0, score + bump), 1)
        factors.append({"factor": f"{len(creds)} exposed employee credential(s)", "points": round(bump, 1)})
    result = {"org_id": org_id, "score": score, "level": level_for(score), "open_alerts": len(alerts),
              "by_class": classes, "exposed_credentials": len(creds), "factors": factors,
              "computed_at": now.isoformat() + "Z"}
    if save:
        org = s.get(Organization, org_id)
        if org:
            org.risk_score, org.risk_level, org.risk_factors, org.risk_updated_at = score, result["level"], factors, now
    return result


def refresh_all(s) -> int:
    n = 0
    for (oid,) in s.query(Organization.id).filter_by(active=True).all():
        compute_org_risk(s, oid)
        n += 1
    return n
