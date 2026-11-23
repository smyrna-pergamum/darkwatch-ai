"""DarkWatch intelligence API (admin): threat actors, entity graph, evidence,
alert intel (classification / risk), IncidentForge escalation."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_

from ..intel import actors as actorsvc
from ..intel import evidence as evsvc
from ..intel.classify import THREAT_CLASSES, classify
from ..intel.graph import NODE_TYPES, build_graph
from ..intel.risk import alert_risk, compute_org_risk, refresh_all
from ..integrations import incidentforge
from ..storage.db import audit, session_scope
from ..storage.models import Alert, Page
from ..storage.models_intel import ActorHandle, AlertOrg, Evidence, Organization, ThreatActor
from .routes import _iso, require_key

router = APIRouter(dependencies=[Depends(require_key)])
ActorKind = Literal["individual", "group", "ransomware_group", "unknown"]


def _alert(s, aid: int) -> Alert:
    a = s.get(Alert, aid)
    if not a:
        raise HTTPException(404, "alert not found")
    return a


def _actor(s, aid: int) -> ThreatActor:
    a = s.get(ThreatActor, aid)
    if not a:
        raise HTTPException(404, "actor not found")
    return a


def _evidence(s, eid: int) -> Evidence:
    e = s.get(Evidence, eid)
    if not e:
        raise HTTPException(404, "evidence not found")
    return e


# ------------------------------------------------------------------ overview
@router.get("/intel/overview")
def overview():
    with session_scope() as s:
        open_q = s.query(Alert).filter(Alert.status.in_(("new", "acknowledged")))
        by_class = dict(open_q.with_entities(Alert.threat_class, func.count(Alert.id)).group_by(Alert.threat_class).all())
        orgs = s.query(Organization).order_by(Organization.risk_score.desc()).limit(8).all()
        actors = s.query(ThreatActor).order_by(ThreatActor.risk_score.desc(), ThreatActor.last_seen.desc()).limit(8).all()
        return {
            "organizations": s.query(func.count(Organization.id)).scalar() or 0,
            "actors": s.query(func.count(ThreatActor.id)).scalar() or 0,
            "evidence": s.query(func.count(Evidence.id)).scalar() or 0,
            "open_by_class": {k or "unclassified": v for k, v in by_class.items()},
            "top_orgs": [{"id": o.id, "name": o.name, "risk_score": o.risk_score, "risk_level": o.risk_level}
                         for o in orgs],
            "top_actors": [actorsvc.actor_dict(s, a) for a in actors],
            "threat_classes": {k: {"label": v[0], "weight": v[1], "mitre": v[2]} for k, v in THREAT_CLASSES.items()},
        }


@router.post("/intel/rescore")
def rescore_all(limit: int = Query(2000, ge=1, le=20000)):
    """Re-classify / re-score recent alerts and refresh every org risk score."""
    from ..intel.orgs import link_alert
    n = 0
    with session_scope() as s:
        for a in s.query(Alert).order_by(Alert.id.desc()).limit(limit):
            if not a.threat_class:
                c = classify(f"{a.title}\n{a.description}", source=a.source)
                a.threat_class = c.threat_class
            link_alert(s, a)
            known = bool(actorsvc.actors_for_alert(s, a.id))
            a.risk_score, a.risk_factors = alert_risk(a, known_actor=known)
            n += 1
        orgs = refresh_all(s)
        for actor in s.query(ThreatActor).all():
            actorsvc.build_profile(s, actor)
    audit("intel.rescore", f"alerts={n} orgs={orgs}", actor="api")
    return {"alerts": n, "organizations": orgs}


@router.get("/threat-classes")
def threat_classes():
    return [{"id": k, "label": v[0], "weight": v[1], "mitre": v[2]} for k, v in THREAT_CLASSES.items()]


# ------------------------------------------------------------------ alert intel
@router.get("/alerts/{aid}/intel")
def alert_intel(aid: int):
    with session_scope() as s:
        a = _alert(s, aid)
        orgs = [s.get(Organization, o) for (o,) in s.query(AlertOrg.org_id).filter_by(alert_id=aid)]
        return {"alert_id": aid, "threat_class": a.threat_class, "classification": (a.triage or {}).get("classification"),
                "risk_score": a.risk_score, "risk_factors": a.risk_factors or [], "incident_ref": a.incident_ref,
                "organizations": [{"id": o.id, "name": o.name} for o in orgs if o],
                "actors": [actorsvc.actor_dict(s, x) for x in actorsvc.actors_for_alert(s, aid) if x],
                "evidence": [evsvc.evidence_dict(s, e) for e in s.query(Evidence).filter_by(alert_id=aid)]}


@router.post("/alerts/{aid}/rescore")
def rescore_alert(aid: int):
    with session_scope() as s:
        a = _alert(s, aid)
        page = s.get(Page, a.page_id) if a.page_id else None
        c = classify(f"{a.title}\n{a.description}\n{(page.content if page else '') or ''}", source=a.source,
                     ai_category=page.ai_category if page and page.ai_analyzed else "")
        a.threat_class = c.threat_class
        tri = dict(a.triage or {})
        tri["classification"] = c.as_dict()
        a.triage = tri
        a.risk_score, a.risk_factors = alert_risk(a, known_actor=bool(actorsvc.actors_for_alert(s, aid)))
        for (oid,) in s.query(AlertOrg.org_id).filter_by(alert_id=aid):
            compute_org_risk(s, oid)
        return {"threat_class": a.threat_class, "classification": c.as_dict(), "risk_score": a.risk_score,
                "risk_factors": a.risk_factors}


# ------------------------------------------------------------------ evidence
class EvidenceIn(BaseModel):
    note: str = Field(default="", max_length=2000)


class HoldIn(BaseModel):
    legal_hold: bool


@router.get("/evidence")
def list_evidence(alert_id: Optional[int] = None, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    with session_scope() as s:
        q = s.query(Evidence)
        if alert_id:
            q = q.filter_by(alert_id=alert_id)
        total = q.count()
        return {"total": total, "items": [evsvc.evidence_dict(s, e) for e in
                                          q.order_by(Evidence.id.desc()).offset(offset).limit(limit)]}


@router.post("/alerts/{aid}/evidence", status_code=201)
def capture_evidence(aid: int, body: EvidenceIn):
    with session_scope() as s:
        ev = evsvc.capture_for_alert(s, _alert(s, aid), actor="api", note=body.note)
        out = evsvc.evidence_dict(s, ev, custody=True)
    audit("evidence.capture", f"alert={aid} evidence={out['id']} sha256={out['sha256']}", actor="api")
    return out


@router.get("/evidence/{eid}")
def get_evidence(eid: int):
    with session_scope() as s:
        return evsvc.evidence_dict(s, _evidence(s, eid), custody=True)


@router.post("/evidence/{eid}/verify")
def verify_evidence(eid: int):
    with session_scope() as s:
        return evsvc.verify(s, _evidence(s, eid), actor="api")


@router.post("/evidence/{eid}/hold")
def legal_hold(eid: int, body: HoldIn):
    with session_scope() as s:
        ev = _evidence(s, eid)
        ev.legal_hold = body.legal_hold
        evsvc.add_custody(s, ev, "hold", "api", "legal hold on" if body.legal_hold else "legal hold off")
        return evsvc.evidence_dict(s, ev, custody=True)


@router.get("/evidence/{eid}/download")
def download_evidence(eid: int):
    with session_scope() as s:
        ev = _evidence(s, eid)
        try:
            data = evsvc.read_content(ev)
        except evsvc.EvidenceError as e:
            raise HTTPException(410, str(e)) from e
        evsvc.add_custody(s, ev, "exported", "api", "downloaded record")
        return Response(data, media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="evidence-{ev.id}-{ev.sha256[:12]}.json"',
            "X-Evidence-SHA256": ev.sha256})


@router.get("/alerts/{aid}/evidence/bundle")
def evidence_bundle(aid: int):
    with session_scope() as s:
        _alert(s, aid)
        try:
            data = evsvc.export_bundle(s, aid, actor="api")
        except evsvc.EvidenceError as e:
            raise HTTPException(404, str(e)) from e
    audit("evidence.bundle", f"alert={aid}", actor="api")
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="darkwatch-alert-{aid}-evidence.zip"'})


# ------------------------------------------------------------------ IncidentForge
@router.post("/alerts/{aid}/incidentforge")
def escalate_incident(aid: int):
    if not incidentforge.configured():
        raise HTTPException(400, "IncidentForge is not configured (INCIDENTFORGE_URL)")
    with session_scope() as s:
        a = _alert(s, aid)
        if not s.query(Evidence).filter_by(alert_id=aid).first():
            evsvc.capture_for_alert(s, a, actor="api", note="captured for IncidentForge escalation")
    try:  # outside any transaction: no DB lock is held during the HTTP call
        ref = incidentforge.escalate_alert(aid, actor="api")
    except incidentforge.IncidentForgeError as e:
        raise HTTPException(502, str(e)) from e
    audit("alert.incidentforge", f"{aid} -> {ref}", actor="api")
    return {"alert_id": aid, "incident_ref": ref}


@router.get("/alerts/{aid}/incidentforge/preview")
def preview_incident(aid: int):
    with session_scope() as s:
        payload = incidentforge.build_payload(s, _alert(s, aid), actor="api")
    for e in payload["evidence"]:
        e.pop("content_b64", None)
    return payload


# ------------------------------------------------------------------ actors
class ActorIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    kind: ActorKind = "individual"
    description: str = Field(default="", max_length=4000)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    handles: list[dict] = Field(default_factory=list, max_length=50)


class ActorPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=200)
    kind: Optional[ActorKind] = None
    description: Optional[str] = Field(default=None, max_length=4000)
    aliases: Optional[list[str]] = Field(default=None, max_length=50)
    tags: Optional[list[str]] = Field(default=None, max_length=30)


class MergeIn(BaseModel):
    other_id: int


@router.get("/actors")
def list_actors(q: Optional[str] = None, kind: Optional[str] = None, limit: int = Query(50, ge=1, le=500),
                offset: int = Query(0, ge=0)):
    with session_scope() as s:
        query = s.query(ThreatActor)
        if kind:
            query = query.filter(ThreatActor.kind == kind)
        if q:
            from ..intel.orgs import like_escape
            like = f"%{like_escape(q)}%"
            hids = [r[0] for r in s.query(ActorHandle.actor_id).filter(ActorHandle.value.ilike(like, escape="\\")).limit(500)]
            query = query.filter(or_(ThreatActor.name.ilike(like, escape="\\"), ThreatActor.id.in_(hids or [-1])))
        total = query.count()
        rows = query.order_by(ThreatActor.risk_score.desc(), ThreatActor.last_seen.desc()).offset(offset).limit(limit)
        return {"total": total, "items": [actorsvc.actor_dict(s, a) for a in rows]}


@router.post("/actors", status_code=201)
def create_actor(body: ActorIn):
    with session_scope() as s:
        if actorsvc._find(s, body.name):
            raise HTTPException(409, "actor already exists")
        a = actorsvc.get_or_create(s, body.name, body.kind)
        a.description, a.aliases = body.description, [x.strip()[:100] for x in body.aliases if x.strip()]
        for h in body.handles:
            p, v = str(h.get("platform", "")).strip().lower(), str(h.get("value", "")).strip()
            if p and v:
                actorsvc.add_handle(s, a, p[:24], v)
        out = actorsvc.actor_dict(s, a, full=True)
    audit("actor.create", f"{out['id']} {out['name']}", actor="api")
    return out


@router.get("/actors/{aid}")
def get_actor(aid: int, rebuild: bool = False):
    with session_scope() as s:
        a = _actor(s, aid)
        if rebuild or not (a.profile or {}).get("built_at"):
            actorsvc.build_profile(s, a)
        return actorsvc.actor_dict(s, a, full=True)


@router.patch("/actors/{aid}")
def patch_actor(aid: int, body: ActorPatch):
    with session_scope() as s:
        a = _actor(s, aid)
        data = body.model_dump(exclude_none=True)
        if "name" in data and data["name"] != a.name:
            other = actorsvc._find(s, data["name"])
            if other and other.id != a.id:
                raise HTTPException(409, "another actor has this name - merge instead")
        for k, v in data.items():
            setattr(a, k, v)
        return actorsvc.actor_dict(s, a, full=True)


@router.post("/actors/{aid}/merge")
def merge_actor(aid: int, body: MergeIn):
    with session_scope() as s:
        try:
            a = actorsvc.merge(s, aid, body.other_id)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        actorsvc.build_profile(s, a)
        out = actorsvc.actor_dict(s, a, full=True)
    audit("actor.merge", f"{body.other_id} -> {aid}", actor="api")
    return out


@router.delete("/actors/{aid}")
def delete_actor(aid: int):
    with session_scope() as s:
        s.delete(_actor(s, aid))
    audit("actor.delete", str(aid), actor="api")
    return {"deleted": aid}


# ------------------------------------------------------------------ graph / changes
@router.get("/graph")
def graph(center: Optional[str] = Query(None, max_length=300), depth: int = Query(2, ge=0, le=4),
          limit: int = Query(150, ge=10, le=500)):
    if center and center.split(":", 1)[0] not in NODE_TYPES:
        raise HTTPException(422, f"center must start with one of {', '.join(NODE_TYPES)}")
    with session_scope() as s:
        return build_graph(s, center, depth, limit)


@router.get("/pages/{pid}/changes")
def page_changes(pid: int):
    with session_scope() as s:
        p = s.get(Page, pid)
        if not p:
            raise HTTPException(404, "page not found")
        return {"page_id": pid, "url": p.url, "changed": p.changed, "crawled_at": _iso(p.crawled_at),
                "previous_hash": p.previous_hash, "content_hash": p.content_hash,
                "change_summary": p.change_summary or {}}
