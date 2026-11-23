"""MISP export: push an alert (with its indicators) as a MISP event."""
from __future__ import annotations

import requests

from config.settings import settings
from ..storage.models import Alert, Sighting

THREAT_LEVEL = {"critical": 1, "high": 1, "medium": 2, "low": 3}
MISP_TYPE = {"ip": "ip-dst", "email": "email-src", "md5": "md5", "sha1": "sha1", "sha256": "sha256",
             "url": "url", "onion": "domain", "domain": "domain", "btc": "btc", "eth": "text",
             "xmr": "xmr", "cve": "vulnerability", "telegram": "text", "jabber": "jabber-id",
             "credential": "text"}


def alert_to_misp_event(s, alert: Alert) -> dict:
    attrs = []
    if alert.url:
        attrs.append({"type": "url", "category": "External analysis", "value": alert.url,
                      "to_ids": False, "comment": "source page"})
    if alert.page_id:
        seen = set()
        for sg in s.query(Sighting).filter_by(page_id=alert.page_id).limit(200):
            ind = sg.indicator
            base = ind.ioc_type.split(":", 1)[-1]
            if (base, ind.value) in seen:
                continue
            seen.add((base, ind.value))
            attrs.append({"type": MISP_TYPE.get(base, "text"), "category": "Network activity"
                          if base in ("ip", "url", "domain", "onion") else "Other",
                          "value": ind.value, "to_ids": False, "comment": f"darkweb-monitor {ind.ioc_type}"})
    return {"Event": {
        "info": f"[darkweb-monitor] {alert.title}"[:250],
        "distribution": 0, "analysis": 0, "threat_level_id": THREAT_LEVEL.get(alert.severity, 2),
        "Tag": [{"name": "tlp:amber"}, {"name": f"darkweb-monitor:source=\"{alert.source}\""}],
        "Attribute": attrs,
    }}


def push_alert(s, alert: Alert) -> dict:
    if not (settings.MISP_URL and settings.MISP_API_KEY):
        raise RuntimeError("MISP_URL / MISP_API_KEY not configured")
    r = requests.post(settings.MISP_URL.rstrip("/") + "/events/add", json=alert_to_misp_event(s, alert),
                      headers={"Authorization": settings.MISP_API_KEY, "Accept": "application/json",
                               "Content-Type": "application/json"},
                      verify=settings.MISP_VERIFY_SSL, timeout=30)
    r.raise_for_status()
    ev = r.json().get("Event", {})
    return {"event_id": ev.get("id"), "uuid": ev.get("uuid")}
