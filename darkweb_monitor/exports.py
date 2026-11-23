"""Exports: CSV, JSON, STIX 2.1 bundle, MISP event JSON."""
from __future__ import annotations

import csv
import io
import json
import uuid

from .storage.models import Indicator

NS = uuid.UUID("6f1c2d6e-9b1a-4bd4-8a35-1f0f3b8f5a10")  # stable ids across exports


def _sid(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + ':' + value)}"


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z") if dt else "1970-01-01T00:00:00.000Z"


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    v = value.replace("\\", "\\\\").replace("'", "\\'")
    base = ioc_type.split(":", 1)[-1]
    return {
        "ip": f"[ipv4-addr:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "onion": f"[domain-name:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "btc": f"[cryptocurrency-wallet:address = '{v}']",
        "eth": f"[cryptocurrency-wallet:address = '{v}']",
        "xmr": f"[cryptocurrency-wallet:address = '{v}']",
    }.get(base)


def indicators_csv(rows: list[Indicator]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "first_seen", "last_seen", "seen_count", "confidence", "on_watchlist", "tags"])
    for i in rows:
        w.writerow([i.ioc_type, i.value, i.first_seen, i.last_seen, i.seen_count, i.confidence,
                    i.on_watchlist, i.tags])
    return buf.getvalue()


def indicators_json(rows: list[Indicator]) -> str:
    return json.dumps([{"type": i.ioc_type, "value": i.value, "first_seen": str(i.first_seen),
                        "last_seen": str(i.last_seen), "seen_count": i.seen_count,
                        "confidence": i.confidence, "on_watchlist": i.on_watchlist, "tags": i.tags}
                       for i in rows], indent=2)


def indicators_stix(rows: list[Indicator]) -> dict:
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", "darkweb-monitor"),
                "created": "2024-01-01T00:00:00.000Z", "modified": "2024-01-01T00:00:00.000Z",
                "name": "darkweb-monitor", "identity_class": "system"}
    objs = [identity]
    for i in rows:
        pat = _stix_pattern(i.ioc_type, i.value)
        if not pat:
            continue
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": _sid("indicator", f"{i.ioc_type}:{i.value}"),
            "created": _ts(i.first_seen), "modified": _ts(i.last_seen), "valid_from": _ts(i.first_seen),
            "name": f"{i.ioc_type}: {i.value}"[:250], "pattern": pat, "pattern_type": "stix",
            "indicator_types": ["malicious-activity"] if not i.on_watchlist else ["compromised"],
            "confidence": int((i.confidence or 0.5) * 100), "created_by_ref": identity["id"],
            "labels": [t for t in (i.tags or "").split(",") if t] + ["dark-web"],
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def indicators_misp(rows: list[Indicator]) -> dict:
    from .integrations.misp import MISP_TYPE
    return {"Event": {
        "info": "darkweb-monitor indicator export", "distribution": 0, "analysis": 0, "threat_level_id": 2,
        "Tag": [{"name": "tlp:amber"}],
        "Attribute": [{"type": MISP_TYPE.get(i.ioc_type.split(":", 1)[-1], "text"), "category": "Other",
                       "value": i.value, "to_ids": False,
                       "first_seen": _ts(i.first_seen), "last_seen": _ts(i.last_seen),
                       "comment": f"{i.ioc_type} seen {i.seen_count}x {i.tags or ''}".strip()} for i in rows]}}
