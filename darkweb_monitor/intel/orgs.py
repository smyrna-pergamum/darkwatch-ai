"""Multi-tenant organisations: assets, alert attribution and tenant API keys."""
from __future__ import annotations

import hashlib
import re
import secrets

from ..storage.models import Alert, WatchItem, utcnow
from ..storage.models_intel import AlertOrg, Organization, OrgApiKey, OrgAsset
from ..watchlist import validate as validate_watch

# asset type -> (watch kind, default severity)
ASSET_TYPES: dict[str, tuple[str, str]] = {
    "domain": ("domain", "high"),
    "brand": ("brand", "medium"),
    "email": ("email", "high"),
    "employee_email": ("email", "high"),
    "executive": ("keyword", "high"),
    "keyword": ("keyword", "medium"),
    "ip": ("ip", "high"),
    "crypto": ("crypto", "medium"),
    "regex": ("regex", "medium"),
}
KEY_PREFIX = "dwk_"
TENANT_ASSET_TYPES = ("domain", "brand", "email", "employee_email", "executive", "ip", "crypto")  # no regex / keyword
MAX_ASSETS_PER_ORG = 5000
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
# registrable-suffix-only values would match every domain under them
_PUBLIC_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr",
                    "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br", "com.cn", "co.in", "co.za",
                    "com.mx", "co.kr", "com.sg", "com.hk", "github.io", "blogspot.com", "appspot.com"}
_EMAIL = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}$")


class OrgError(ValueError):
    pass


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:80] or "org"


def create_org(s, name: str, *, sector: str = "", country: str = "", description: str = "") -> Organization:
    name = (name or "").strip()
    if len(name) < 2:
        raise OrgError("organisation name must be at least 2 characters")
    if s.query(Organization).filter_by(name=name).first():
        raise OrgError("organisation already exists")
    base = slug = slugify(name)
    i = 2
    while s.query(Organization).filter_by(slug=slug).first():
        slug, i = f"{base}-{i}", i + 1
    org = Organization(name=name[:200], slug=slug, sector=sector[:64], country=country[:64],
                       description=description[:4000])
    s.add(org)
    s.flush()
    return org


def like_escape(v: str) -> str:
    """Escape LIKE wildcards; use with ``.like(pattern, escape="\\")``."""
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def valid_domain(value: str) -> str | None:
    if not _DOMAIN.match(value):
        return "invalid domain (expected e.g. example.com)"
    if value in _PUBLIC_SUFFIXES:
        return "public suffixes cannot be registered as an asset"
    return None


class OwnershipError(OrgError):
    pass


def add_asset(s, org_id: int, asset_type: str, value: str, *, severity: str | None = None,
              label: str = "", tenant: bool = False) -> tuple[OrgAsset, bool]:
    """Attach an asset to an org. Admins may share an existing watch item between
    organisations (with backfill of past alerts). Tenants may only register values
    nobody watches yet - otherwise a tenant could claim another company's domain
    and inherit its alerts - and cannot add regex / keyword assets."""
    if asset_type not in ASSET_TYPES:
        raise OrgError(f"asset_type must be one of {', '.join(ASSET_TYPES)}")
    if tenant and asset_type not in TENANT_ASSET_TYPES:
        raise OrgError(f"tenants may add: {', '.join(TENANT_ASSET_TYPES)}")
    kind, default_sev = ASSET_TYPES[asset_type]
    value = (value or "").strip()
    if kind in ("domain", "email"):
        value = value.lower().lstrip("@") if kind == "domain" else value.lower()
    err = validate_watch(kind, value)
    if not err and kind == "email" and not _EMAIL.match(value):
        err = "invalid e-mail address"
    if not err and kind == "domain":
        err = valid_domain(value)
    if err:
        raise OrgError(err)
    w = s.query(WatchItem).filter_by(kind=kind, value=value).first()
    if w and tenant:
        if s.query(OrgAsset).filter_by(org_id=org_id, watch_id=w.id).first():
            return s.query(OrgAsset).filter_by(org_id=org_id, watch_id=w.id).first(), False
        raise OwnershipError("this value is already monitored - ask an administrator to assign it")
    if s.query(OrgAsset).filter_by(org_id=org_id).count() >= MAX_ASSETS_PER_ORG:
        raise OrgError(f"asset limit reached ({MAX_ASSETS_PER_ORG})")
    if not w:
        w = WatchItem(kind=kind, value=value, severity=severity or default_sev, source="org",
                      note=f"asset of org #{org_id}")
        s.add(w)
        s.flush()
    elif not w.active:
        w.active = True
    existing = s.query(OrgAsset).filter_by(org_id=org_id, watch_id=w.id).first()
    if existing:
        return existing, False
    a = OrgAsset(org_id=org_id, watch_id=w.id, asset_type=asset_type, label=label[:200])
    s.add(a)
    s.flush()
    link_existing_alerts(s, org_id, {w.id})
    return a, True


def remove_asset(s, org_id: int, asset_id: int) -> bool:
    a = s.query(OrgAsset).filter_by(id=asset_id, org_id=org_id).first()
    if not a:
        return False
    wid = a.watch_id
    s.delete(a)
    s.flush()
    still_used = s.query(OrgAsset).filter_by(watch_id=wid).count()
    w = s.get(WatchItem, wid)
    if w and not still_used and w.source == "org":
        s.delete(w)
    return True


def asset_dict(s, a: OrgAsset) -> dict:
    w = s.get(WatchItem, a.watch_id)
    return {"id": a.id, "org_id": a.org_id, "asset_type": a.asset_type, "label": a.label,
            "watch_id": a.watch_id, "value": w.value if w else "", "kind": w.kind if w else "",
            "severity": w.severity if w else "", "active": bool(w and w.active),
            "created_at": a.created_at.isoformat() + "Z" if a.created_at else None}


def orgs_for_matches(s, matches: list | None) -> set[int]:
    ids = {m.get("id") for m in (matches or []) if isinstance(m, dict) and m.get("id")}
    if not ids:
        return set()
    return {r[0] for r in s.query(OrgAsset.org_id).filter(OrgAsset.watch_id.in_(ids)).all()}


def link_alert(s, alert: Alert) -> set[int]:
    org_ids = orgs_for_matches(s, alert.matches)
    have = {r[0] for r in s.query(AlertOrg.org_id).filter_by(alert_id=alert.id).all()}
    for oid in org_ids - have:
        s.add(AlertOrg(alert_id=alert.id, org_id=oid))
    if org_ids - have:
        s.flush()
    return org_ids


def link_existing_alerts(s, org_id: int, watch_ids: set[int], scan: int = 5000) -> int:
    """Backfill: attribute already-raised alerts that matched newly added assets."""
    n = 0
    have = {r[0] for r in s.query(AlertOrg.alert_id).filter_by(org_id=org_id).all()}
    for a in s.query(Alert).order_by(Alert.id.desc()).limit(scan):
        if a.id in have:
            continue
        if any(isinstance(m, dict) and m.get("id") in watch_ids for m in (a.matches or [])):
            s.add(AlertOrg(alert_id=a.id, org_id=org_id))
            n += 1
    if n:
        s.flush()
    return n


def org_alert_ids(s, org_id: int) -> list[int]:
    return [r[0] for r in s.query(AlertOrg.alert_id).filter_by(org_id=org_id).all()]


# ------------------------------------------------------------------ API keys
def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_key(s, org_id: int, name: str = "") -> tuple[OrgApiKey, str]:
    """Return (record, plaintext). The plaintext is shown once and never stored."""
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    k = OrgApiKey(org_id=org_id, name=name[:100], prefix=raw[:10], key_hash=_hash(raw))
    s.add(k)
    s.flush()
    return k, raw


def resolve_key(s, raw: str | None) -> OrgApiKey | None:
    if not raw or not raw.startswith(KEY_PREFIX):
        return None
    k = s.query(OrgApiKey).filter_by(key_hash=_hash(raw), active=True).first()
    if k:
        k.last_used = utcnow()
    return k
