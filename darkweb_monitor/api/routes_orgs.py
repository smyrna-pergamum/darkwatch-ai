"""Multi-tenant organisation API.

Admin (``API_KEY``) manages organisations and tenant keys. A tenant key
(``dwk_...``) only opens ``/api/orgs/{its org}/...``: assets, alerts, risk,
exposure and evidence of that organisation."""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func

from config.settings import settings
from ..intel import orgs as orgsvc
from ..intel.evidence import evidence_dict
from ..intel.risk import compute_org_risk, exposed_credentials, org_domains
from ..storage.db import audit, session_scope
from ..storage.models import Alert, Indicator
from ..storage.models_intel import ActorSighting, AlertOrg, Evidence, Organization, OrgApiKey, OrgAsset, ThreatActor
from .routes import _iso, alert_dict, require_key

router = APIRouter()
_WATCH_TITLE = re.compile(r"^Watchlist hit \[[^\]]*\]")
AssetType = Literal["domain", "brand", "email", "employee_email", "executive", "keyword", "ip", "crypto", "regex"]
Sev = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Caller:
    role: str  # admin | tenant
    org_id: Optional[int]
    actor: str


def org_scope(org_id: int, x_api_key: Optional[str] = Header(default=None)) -> Caller:
    if x_api_key and settings.API_KEY and hmac.compare_digest(x_api_key, settings.API_KEY):
        return Caller("admin", None, "admin")
    if x_api_key and x_api_key.startswith(orgsvc.KEY_PREFIX):
        with session_scope() as s:
            k = orgsvc.resolve_key(s, x_api_key)
            if not k:
                raise HTTPException(401, "invalid or revoked organisation key")
            if k.org_id != org_id:
                raise HTTPException(403, "this key belongs to another organisation")
            return Caller("tenant", k.org_id, f"org-key:{k.prefix}")
    if not settings.API_KEY:
        return Caller("admin", None, "user")
    raise HTTPException(401, "invalid or missing X-API-Key")


def _org(s, org_id: int) -> Organization:
    o = s.get(Organization, org_id)
    if not o:
        raise HTTPException(404, "organisation not found")
    return o


def org_dict(s, o: Organization) -> dict:
    assets = s.query(func.count(OrgAsset.id)).filter_by(org_id=o.id).scalar() or 0
    open_alerts = (s.query(func.count(Alert.id)).join(AlertOrg, AlertOrg.alert_id == Alert.id)
                   .filter(AlertOrg.org_id == o.id, Alert.status.in_(("new", "acknowledged"))).scalar() or 0)
    return {"id": o.id, "name": o.name, "slug": o.slug, "sector": o.sector, "country": o.country,
            "description": o.description, "active": o.active, "risk_score": o.risk_score or 0,
            "risk_level": o.risk_level or "low", "risk_factors": o.risk_factors or [],
            "risk_updated_at": _iso(o.risk_updated_at), "assets": assets, "open_alerts": open_alerts,
            "created_at": _iso(o.created_at)}


def scoped_alert(s, a: Alert, who: Caller, org_id: int) -> dict:
    """Tenants share alerts that matched several organisations: show a tenant only
    its own matches and no internal analyst / triage notes."""
    d = alert_dict(a)
    if who.role != "tenant":
        return d
    own = {r[0] for r in s.query(OrgAsset.watch_id).filter_by(org_id=org_id).all()}
    d["matches"] = [m for m in d["matches"] if isinstance(m, dict) and m.get("id") in own]
    d["analyst_note"] = ""
    d["triage"] = {k: v for k, v in (d["triage"] or {}).items() if k == "classification"}
    d["risk_factors"] = [f for f in d["risk_factors"] if "matched" not in f.get("factor", "")]
    if a.matches and len(d["matches"]) != len([m for m in a.matches if isinstance(m, dict)]):
        d["description"] = "(details shared with other organisations are hidden)"
        own_terms = ", ".join(sorted({m["value"] for m in d["matches"]})[:5])
        d["title"] = _WATCH_TITLE.sub(f"Watchlist hit [{own_terms}]", d["title"], count=1)
    return d


# ------------------------------------------------------------------ schemas
class AssetIn(BaseModel):
    asset_type: AssetType = "domain"
    value: str = Field(min_length=1, max_length=512)
    severity: Optional[Sev] = None
    label: str = Field(default="", max_length=200)


class OrgIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    sector: str = Field(default="", max_length=64)
    country: str = Field(default="", max_length=64)
    description: str = Field(default="", max_length=4000)
    assets: list[AssetIn] = Field(default_factory=list, max_length=500)


class OrgPatch(BaseModel):
    sector: Optional[str] = Field(default=None, max_length=64)
    country: Optional[str] = Field(default=None, max_length=64)
    description: Optional[str] = Field(default=None, max_length=4000)
    active: Optional[bool] = None


class BulkAssets(BaseModel):
    asset_type: AssetType = "employee_email"
    text: str = Field(max_length=200_000)
    severity: Optional[Sev] = None


class KeyIn(BaseModel):
    name: str = Field(default="", max_length=100)


# ------------------------------------------------------------------ admin
@router.get("/orgs", dependencies=[Depends(require_key)])
def list_orgs():
    with session_scope() as s:
        return [org_dict(s, o) for o in s.query(Organization).order_by(Organization.risk_score.desc(), Organization.name)]


@router.post("/orgs", status_code=201, dependencies=[Depends(require_key)])
def create_org(body: OrgIn):
    with session_scope() as s:
        try:
            o = orgsvc.create_org(s, body.name, sector=body.sector, country=body.country,
                                  description=body.description)
            errors = []
            for a in body.assets:
                try:
                    orgsvc.add_asset(s, o.id, a.asset_type, a.value, severity=a.severity, label=a.label)
                except orgsvc.OrgError as e:
                    errors.append({"value": a.value, "error": str(e)})
        except orgsvc.OrgError as e:
            raise HTTPException(409 if "exists" in str(e) else 422, str(e)) from e
        compute_org_risk(s, o.id)
        out = {**org_dict(s, o), "asset_errors": errors}
    audit("org.create", f"{out['id']} {out['name']} assets={out['assets']}", actor="api")
    return out


@router.patch("/orgs/{org_id}", dependencies=[Depends(require_key)])
def patch_org(org_id: int, body: OrgPatch):
    with session_scope() as s:
        o = _org(s, org_id)
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(o, k, v)
        return org_dict(s, o)


@router.delete("/orgs/{org_id}", dependencies=[Depends(require_key)])
def delete_org(org_id: int):
    with session_scope() as s:
        o = _org(s, org_id)
        for a in s.query(OrgAsset).filter_by(org_id=org_id).all():
            orgsvc.remove_asset(s, org_id, a.id)
        s.query(AlertOrg).filter_by(org_id=org_id).delete()
        s.query(OrgApiKey).filter_by(org_id=org_id).delete()
        s.delete(o)
    audit("org.delete", str(org_id), actor="api")
    return {"deleted": org_id}


@router.get("/orgs/{org_id}/keys", dependencies=[Depends(require_key)])
def list_keys(org_id: int):
    with session_scope() as s:
        _org(s, org_id)
        return [{"id": k.id, "name": k.name, "prefix": k.prefix, "active": k.active,
                 "created_at": _iso(k.created_at), "last_used": _iso(k.last_used)}
                for k in s.query(OrgApiKey).filter_by(org_id=org_id).order_by(OrgApiKey.id)]


@router.post("/orgs/{org_id}/keys", status_code=201, dependencies=[Depends(require_key)])
def create_key(org_id: int, body: KeyIn):
    with session_scope() as s:
        _org(s, org_id)
        k, raw = orgsvc.create_key(s, org_id, body.name)
        out = {"id": k.id, "name": k.name, "prefix": k.prefix, "key": raw,
               "note": "Store this key now - it is not shown again."}
    audit("org.key.create", f"org={org_id} key={out['prefix']}", actor="api")
    return out


@router.delete("/orgs/{org_id}/keys/{key_id}", dependencies=[Depends(require_key)])
def revoke_key(org_id: int, key_id: int):
    with session_scope() as s:
        k = s.query(OrgApiKey).filter_by(id=key_id, org_id=org_id).first()
        if not k:
            raise HTTPException(404, "key not found")
        k.active = False
    audit("org.key.revoke", f"org={org_id} key={key_id}", actor="api")
    return {"revoked": key_id}


# ------------------------------------------------------------------ tenant
@router.get("/orgs/{org_id}")
def get_org(org_id: int, who: Caller = Depends(org_scope)):
    with session_scope() as s:
        return {**org_dict(s, _org(s, org_id)), "role": who.role}


@router.get("/orgs/{org_id}/assets")
def list_assets(org_id: int, who: Caller = Depends(org_scope)):
    with session_scope() as s:
        _org(s, org_id)
        return [orgsvc.asset_dict(s, a) for a in s.query(OrgAsset).filter_by(org_id=org_id).order_by(OrgAsset.id)]


@router.post("/orgs/{org_id}/assets", status_code=201)
def add_asset(org_id: int, body: AssetIn, who: Caller = Depends(org_scope)):
    with session_scope() as s:
        _org(s, org_id)
        try:
            a, created = orgsvc.add_asset(s, org_id, body.asset_type, body.value, severity=body.severity,
                                          label=body.label, tenant=who.role == "tenant")
        except orgsvc.OwnershipError as e:
            raise HTTPException(409, str(e)) from e
        except orgsvc.OrgError as e:
            raise HTTPException(422, str(e)) from e
        if not created:
            raise HTTPException(409, "asset already registered")
        compute_org_risk(s, org_id)
        out = orgsvc.asset_dict(s, a)
    audit("org.asset.add", f"org={org_id} {body.asset_type}={body.value}", actor=who.actor)
    return out


@router.post("/orgs/{org_id}/assets/bulk")
def bulk_assets(org_id: int, body: BulkAssets, who: Caller = Depends(org_scope)):
    values = [v.strip() for v in body.text.replace(",", "\n").replace(";", "\n").splitlines() if v.strip()]
    added, skipped, errors = 0, 0, []
    with session_scope() as s:
        _org(s, org_id)
        for v in values[:5000]:
            try:
                _, created = orgsvc.add_asset(s, org_id, body.asset_type, v, severity=body.severity,
                                              tenant=who.role == "tenant")
                added += int(created)
                skipped += int(not created)
            except orgsvc.OrgError as e:
                errors.append({"value": v[:200], "error": str(e)})
        compute_org_risk(s, org_id)
    audit("org.asset.bulk", f"org={org_id} type={body.asset_type} added={added}", actor=who.actor)
    return {"added": added, "skipped": skipped, "errors": errors[:100], "total": len(values)}


@router.delete("/orgs/{org_id}/assets/{asset_id}")
def remove_asset(org_id: int, asset_id: int, who: Caller = Depends(org_scope)):
    with session_scope() as s:
        if not orgsvc.remove_asset(s, org_id, asset_id):
            raise HTTPException(404, "asset not found")
    audit("org.asset.remove", f"org={org_id} asset={asset_id}", actor=who.actor)
    return {"deleted": asset_id}


@router.get("/orgs/{org_id}/alerts")
def org_alerts(org_id: int, who: Caller = Depends(org_scope), status: Optional[str] = None,
               threat_class: Optional[str] = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    with session_scope() as s:
        _org(s, org_id)
        q = s.query(Alert).join(AlertOrg, AlertOrg.alert_id == Alert.id).filter(AlertOrg.org_id == org_id)
        if status == "open":
            q = q.filter(Alert.status.in_(("new", "acknowledged")))
        elif status:
            q = q.filter(Alert.status.in_(status.split(",")))
        if threat_class:
            q = q.filter(Alert.threat_class == threat_class)
        total = q.count()
        rows = q.order_by(Alert.risk_score.desc(), Alert.last_seen.desc()).offset(offset).limit(limit).all()
        return {"total": total, "items": [scoped_alert(s, a, who, org_id) for a in rows]}


@router.get("/orgs/{org_id}/alerts/{alert_id}")
def org_alert(org_id: int, alert_id: int, who: Caller = Depends(org_scope)):
    with session_scope() as s:
        if not s.query(AlertOrg).filter_by(org_id=org_id, alert_id=alert_id).first():
            raise HTTPException(404, "alert not found for this organisation")
        return scoped_alert(s, s.get(Alert, alert_id), who, org_id)


@router.get("/orgs/{org_id}/risk")
def org_risk(org_id: int, who: Caller = Depends(org_scope)):
    with session_scope() as s:
        _org(s, org_id)
        return compute_org_risk(s, org_id)


@router.get("/orgs/{org_id}/exposure")
def org_exposure(org_id: int, who: Caller = Depends(org_scope)):
    """Employee credential / e-mail exposure, ransomware listings and actors."""
    with session_scope() as s:
        _org(s, org_id)
        domains = org_domains(s, org_id)
        creds = exposed_credentials(s, org_id)
        emails = []
        for d in domains:
            emails += (s.query(Indicator).filter(Indicator.ioc_type == "email",
                                                 Indicator.value.like(f"%@{orgsvc.like_escape(d)}", escape="\\"))
                       .order_by(Indicator.last_seen.desc()).limit(200).all())
        alert_ids = orgsvc.org_alert_ids(s, org_id)
        ransomware = (s.query(Alert).filter(Alert.id.in_(alert_ids), Alert.threat_class == "ransomware")
                      .order_by(Alert.created_at.desc()).limit(50).all()) if alert_ids else []
        actors = []
        if alert_ids:
            rows = (s.query(ActorSighting.actor_id, func.count(ActorSighting.id))
                    .filter(ActorSighting.alert_id.in_(alert_ids)).group_by(ActorSighting.actor_id)
                    .order_by(func.count(ActorSighting.id).desc()).limit(20).all())
            for aid, n in rows:
                a = s.get(ThreatActor, aid)
                if a:
                    actors.append({"id": a.id, "name": a.name, "kind": a.kind, "mentions": n, "risk_score": a.risk_score})
        by_class = dict(s.query(Alert.threat_class, func.count(Alert.id)).filter(Alert.id.in_(alert_ids))
                        .group_by(Alert.threat_class).all()) if alert_ids else {}

        def ind(i: Indicator) -> dict:
            return {"id": i.id, "type": i.ioc_type, "value": i.value, "first_seen": _iso(i.first_seen),
                    "last_seen": _iso(i.last_seen), "seen_count": i.seen_count, "tags": i.tags}
        return {"domains": domains, "exposed_credentials": [ind(i) for i in creds],
                "exposed_emails": [ind(i) for i in emails[:200]],
                "ransomware_listings": [scoped_alert(s, a, who, org_id) for a in ransomware], "threat_actors": actors,
                "alerts_by_class": {k or "unclassified": v for k, v in by_class.items()}}


@router.get("/orgs/{org_id}/evidence")
def org_evidence(org_id: int, who: Caller = Depends(org_scope), limit: int = Query(100, ge=1, le=500)):
    with session_scope() as s:
        _org(s, org_id)
        ids = orgsvc.org_alert_ids(s, org_id)
        if not ids:
            return []
        rows = (s.query(Evidence).filter(Evidence.alert_id.in_(ids)).order_by(Evidence.id.desc()).limit(limit))
        return [evidence_dict(s, e) for e in rows]
