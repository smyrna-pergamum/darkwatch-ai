"""Entity relationship graph built on demand from the database.

Node ids are ``<type>:<key>``: org, asset (watch item), alert, site (host),
indicator, actor, handle. ``build_graph`` expands breadth-first from a centre
node (or from all organisations and the riskiest actors) up to a node limit."""
from __future__ import annotations

from collections import deque
from urllib.parse import urlparse

from ..storage.models import Alert, Indicator, Page, Sighting, WatchItem
from ..storage.models_intel import ActorHandle, ActorSighting, AlertOrg, Organization, OrgAsset, ThreatActor

NODE_TYPES = ("org", "asset", "alert", "site", "indicator", "actor", "handle")
CONTACT_PLATFORMS = ("telegram", "jabber", "tox", "session", "email", "crypto")
FANOUT = 25


def _host(url: str) -> str:
    try:
        return (urlparse(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _node(s, nid: str) -> dict | None:
    t, _, key = nid.partition(":")
    if t == "site":
        return {"id": nid, "type": "site", "label": key} if key else None
    if not key.isdigit():
        return None
    k = int(key)
    if t == "org":
        o = s.get(Organization, k)
        return o and {"id": nid, "type": t, "label": o.name, "risk": o.risk_score, "level": o.risk_level}
    if t == "asset":
        w = s.get(WatchItem, k)
        return w and {"id": nid, "type": t, "label": f"{w.kind}: {w.value}", "severity": w.severity}
    if t == "alert":
        a = s.get(Alert, k)
        return a and {"id": nid, "type": t, "label": a.title[:80], "severity": a.severity, "risk": a.risk_score,
                      "threat_class": a.threat_class, "status": a.status}
    if t == "indicator":
        i = s.get(Indicator, k)
        return i and {"id": nid, "type": t, "label": f"{i.ioc_type}: {i.value[:60]}", "watch": i.on_watchlist}
    if t == "actor":
        a = s.get(ThreatActor, k)
        return a and {"id": nid, "type": t, "label": a.name, "kind": a.kind, "risk": a.risk_score}
    if t == "handle":
        h = s.get(ActorHandle, k)
        return h and {"id": nid, "type": t, "label": f"{h.platform}: {h.value[:60]}"}
    return None


def _alerts_matching_watch(s, wid: int, scan: int = 2000) -> list[int]:
    out = []
    for a in s.query(Alert).order_by(Alert.id.desc()).limit(scan):
        if any(isinstance(m, dict) and m.get("id") == wid for m in (a.matches or [])):
            out.append(a.id)
            if len(out) >= FANOUT:
                break
    return out


def neighbours(s, nid: str) -> list[tuple[str, str]]:
    """Return [(neighbour_id, relation)]."""
    t, _, key = nid.partition(":")
    out: list[tuple[str, str]] = []
    if t == "site":
        from .orgs import like_escape
        e = like_escape(key)
        for (aid,) in (s.query(Alert.id).filter(Alert.url.like(f"%://{e}/%", escape="\\")
                                                | Alert.url.like(f"%://{e}", escape="\\"))
                       .order_by(Alert.id.desc()).limit(FANOUT)):
            out.append((f"alert:{aid}", "observed on"))
        for (aid,) in s.query(ActorSighting.actor_id).filter_by(host=key).distinct().limit(FANOUT):
            out.append((f"actor:{aid}", "active on"))
        return out
    if not key.isdigit():
        return out
    k = int(key)
    if t == "org":
        out += [(f"asset:{w}", "monitors") for (w,) in s.query(OrgAsset.watch_id).filter_by(org_id=k).limit(FANOUT * 2)]
        out += [(f"alert:{a}", "concerns") for (a,) in s.query(AlertOrg.alert_id).filter_by(org_id=k)
                .order_by(AlertOrg.alert_id.desc()).limit(FANOUT)]
    elif t == "asset":
        out += [(f"org:{o}", "monitors") for (o,) in s.query(OrgAsset.org_id).filter_by(watch_id=k)]
        out += [(f"alert:{a}", "matched") for a in _alerts_matching_watch(s, k)]
    elif t == "alert":
        a = s.get(Alert, k)
        if not a:
            return out
        out += [(f"org:{o}", "concerns") for (o,) in s.query(AlertOrg.org_id).filter_by(alert_id=k)]
        out += [(f"asset:{m['id']}", "matched") for m in (a.matches or []) if isinstance(m, dict) and m.get("id")]
        h = _host(a.url)
        if h:
            out.append((f"site:{h}", "observed on"))
        out += [(f"actor:{x}", "linked actor") for (x,) in
                s.query(ActorSighting.actor_id).filter_by(alert_id=k).distinct()]
        if a.page_id:
            out += [(f"indicator:{i}", "contains") for (i,) in
                    s.query(Sighting.indicator_id).filter_by(page_id=a.page_id).distinct().limit(FANOUT)]
    elif t == "indicator":
        pages = [p for (p,) in s.query(Sighting.page_id).filter_by(indicator_id=k).distinct().limit(FANOUT)]
        hosts = {_host(u) for (u,) in s.query(Page.url).filter(Page.id.in_(pages))} if pages else set()
        out += [(f"site:{h}", "seen on") for h in sorted(hosts) if h]
        if pages:
            out += [(f"alert:{a}", "contains") for (a,) in
                    s.query(Alert.id).filter(Alert.page_id.in_(pages)).limit(FANOUT)]
    elif t == "actor":
        out += [(f"site:{h}", "active on") for (h,) in
                s.query(ActorSighting.host).filter_by(actor_id=k).distinct().limit(FANOUT) if h]
        alert_ids = [a for (a,) in s.query(ActorSighting.alert_id).filter_by(actor_id=k).distinct().limit(FANOUT) if a]
        out += [(f"alert:{a}", "linked actor") for a in alert_ids]
        if alert_ids:
            out += [(f"org:{o}", "targets") for (o,) in
                    s.query(AlertOrg.org_id).filter(AlertOrg.alert_id.in_(alert_ids)).distinct()]
        out += [(f"handle:{h}", "uses") for (h,) in s.query(ActorHandle.id)
                .filter(ActorHandle.actor_id == k, ActorHandle.platform.in_(CONTACT_PLATFORMS)).limit(FANOUT)]
    elif t == "handle":
        h = s.get(ActorHandle, k)
        if h:
            out.append((f"actor:{h.actor_id}", "uses"))
    return out


def _seeds(s) -> list[str]:
    seeds = [f"org:{o}" for (o,) in s.query(Organization.id).filter_by(active=True).limit(20)]
    seeds += [f"actor:{a}" for (a,) in s.query(ThreatActor.id).order_by(ThreatActor.risk_score.desc()).limit(15)]
    return seeds


def build_graph(s, center: str | None = None, depth: int = 2, limit: int = 150) -> dict:
    depth = max(0, min(depth, 4))
    limit = max(10, min(limit, 500))
    seeds = [center] if center else _seeds(s)
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], str] = {}
    q: deque[tuple[str, int]] = deque()
    for sd in seeds:
        n = _node(s, sd)
        if n:
            nodes[sd] = n
            q.append((sd, 0))
    truncated = False
    while q:
        nid, d = q.popleft()
        if d >= depth:
            continue
        for nb, rel in neighbours(s, nid):
            if nb not in nodes:
                if len(nodes) >= limit:
                    truncated = True
                    continue
                n = _node(s, nb)
                if not n:
                    continue
                nodes[nb] = n
                q.append((nb, d + 1))
            key = tuple(sorted((nid, nb)))
            edges.setdefault(key, rel)
    return {"nodes": list(nodes.values()),
            "edges": [{"source": a, "target": b, "relation": r} for (a, b), r in edges.items()],
            "center": center, "depth": depth, "truncated": truncated}
