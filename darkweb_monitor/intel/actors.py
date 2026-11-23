"""Threat actor profiling.

Actors come from three places:
- forum authors whose posts mention watched assets (forum monitoring),
- contact handles (Telegram, Jabber, Tox, Session) inside those posts,
- ransomware groups that list a watched organisation as a victim.

A nickname seen on several forums is treated as one actor (with one handle
per forum); analysts can merge actors that turn out to be the same."""
from __future__ import annotations

import re
from collections import Counter
from datetime import timedelta

from sqlalchemy import func

from ..crawler.forum import ForumPost, clean_handle
from ..storage.models import Alert, Indicator, Sighting, utcnow
from ..storage.models_intel import ActorHandle, ActorSighting, AlertOrg, Organization, ThreatActor

_RANSOM_TITLE = re.compile(r"group '([^']{2,80})'", re.IGNORECASE)
KINDS = ("individual", "group", "ransomware_group", "unknown")


def _find(s, name: str) -> ThreatActor | None:
    low = name.lower()
    a = s.query(ThreatActor).filter(func.lower(ThreatActor.name) == low).first()
    if a:
        return a
    for cand in s.query(ThreatActor).filter(ThreatActor.aliases.isnot(None)).limit(5000):
        if any(str(x).lower() == low for x in (cand.aliases or [])):
            return cand
    return None


def get_or_create(s, name: str, kind: str = "individual") -> ThreatActor:
    name = name.strip()[:200]
    a = _find(s, name)
    if a:
        return a
    a = ThreatActor(name=name, kind=kind if kind in KINDS else "unknown", aliases=[], tags=[], profile={},
                    mention_count=0)
    s.add(a)
    s.flush()
    return a


def add_handle(s, actor: ThreatActor, platform: str, value: str) -> ActorHandle:
    value = value.strip()[:300]
    h = s.query(ActorHandle).filter_by(platform=platform, value=value).first()
    now = utcnow()
    if h:
        h.last_seen = now
        if h.actor_id != actor.id:
            # same contact used by two actors -> strong link, record it on both
            other = s.get(ThreatActor, h.actor_id)
            if other:
                _tag(actor, f"shares {platform} with {other.name}")
                _tag(other, f"shares {platform} with {actor.name}")
        return h
    h = ActorHandle(actor_id=actor.id, platform=platform, value=value, first_seen=now, last_seen=now)
    s.add(h)
    s.flush()
    return h


def _tag(actor: ThreatActor, tag: str) -> None:
    tags = list(actor.tags or [])
    if tag not in tags:
        actor.tags = (tags + [tag])[-30:]


def _sighting(s, actor: ThreatActor, *, source: str, host: str = "", page_id=None, alert_id=None,
              context: str = "") -> None:
    now = utcnow()
    actor.last_seen = now
    actor.mention_count = (actor.mention_count or 0) + 1
    s.add(ActorSighting(actor_id=actor.id, page_id=page_id, alert_id=alert_id, source=source, host=host[:256],
                        context=context[:600], ts=now))


def ingest_forum_posts(s, posts: list[ForumPost], *, host: str, page_id: int | None,
                       watch_terms: list[str], alert_id: int | None = None) -> list[int]:
    """Profile authors of posts that mention a watched term. When the page was
    alerted but no single post matched (e.g. the hit was in the title), the
    thread starter is profiled. Returns actor ids."""
    terms = [t.lower() for t in watch_terms if t and len(t) >= 3]
    relevant = [p for p in posts if any(t in p.body.lower() for t in terms)]
    if not relevant and alert_id and posts:
        relevant = posts[:1]
    ids = []
    for p in relevant[:25]:
        nick = clean_handle(p.author)
        if not nick:
            continue
        actor = get_or_create(s, nick, "individual")
        add_handle(s, actor, "forum", f"{nick}@{host}" if host else nick)
        for platform, value in p.contacts:
            add_handle(s, actor, platform, value)
        ids.append(actor.id)
        s.flush()
        if s.query(ActorSighting).filter_by(actor_id=actor.id, page_id=page_id,
                                            context=p.body[:600]).first():
            continue  # same post seen again on a re-crawl: not a new mention
        _sighting(s, actor, source="forum", host=host, page_id=page_id, alert_id=alert_id, context=p.body[:600])
    return ids


def ingest_ransomware_alert(s, alert: Alert) -> int | None:
    m = _RANSOM_TITLE.search(alert.title or "")
    if not m:
        return None
    actor = get_or_create(s, m.group(1).strip(), "ransomware_group")
    if actor.kind == "individual":
        actor.kind = "ransomware_group"
    _tag(actor, "ransomware")
    exists = s.query(ActorSighting).filter_by(actor_id=actor.id, alert_id=alert.id).first()
    if not exists:
        _sighting(s, actor, source="ransomware", alert_id=alert.id, context=alert.title)
    return actor.id


def actors_for_alert(s, alert_id: int) -> list[ThreatActor]:
    s.flush()
    ids = {r[0] for r in s.query(ActorSighting.actor_id).filter_by(alert_id=alert_id).all()}
    return [s.get(ThreatActor, i) for i in sorted(ids)]


def merge(s, keep_id: int, other_id: int) -> ThreatActor:
    if keep_id == other_id:
        raise ValueError("cannot merge an actor into itself")
    keep, other = s.get(ThreatActor, keep_id), s.get(ThreatActor, other_id)
    if not keep or not other:
        raise ValueError("actor not found")
    s.query(ActorHandle).filter_by(actor_id=other.id).update({"actor_id": keep.id})
    s.query(ActorSighting).filter_by(actor_id=other.id).update({"actor_id": keep.id})
    keep.aliases = sorted(set((keep.aliases or []) + (other.aliases or []) + [other.name]) - {keep.name})
    keep.tags = list(dict.fromkeys((keep.tags or []) + (other.tags or [])))[-30:]
    keep.mention_count = (keep.mention_count or 0) + (other.mention_count or 0)
    keep.first_seen = min(filter(None, [keep.first_seen, other.first_seen]), default=keep.first_seen)
    keep.last_seen = max(filter(None, [keep.last_seen, other.last_seen]), default=keep.last_seen)
    s.flush()
    s.delete(other)
    s.flush()
    return keep


def build_profile(s, actor: ThreatActor) -> dict:
    """Derived profile: activity, venues, targets, linked indicators, risk."""
    s.flush()  # autoflush is off: make new sightings visible
    sights = s.query(ActorSighting).filter_by(actor_id=actor.id).order_by(ActorSighting.ts.desc()).limit(2000).all()
    hosts = Counter(x.host for x in sights if x.host)
    alert_ids = {x.alert_id for x in sights if x.alert_id}
    page_ids = {x.page_id for x in sights if x.page_id}
    alerts = [s.get(Alert, i) for i in sorted(alert_ids)]
    alerts = [a for a in alerts if a]
    orgs = Counter()
    if alert_ids:
        for (oid,) in s.query(AlertOrg.org_id).filter(AlertOrg.alert_id.in_(alert_ids)).all():
            org = s.get(Organization, oid)
            if org:
                orgs[org.name] += 1
    classes = Counter(a.threat_class for a in alerts if a.threat_class)
    wallets = []
    if page_ids:
        q = (s.query(Indicator).join(Sighting, Sighting.indicator_id == Indicator.id)
             .filter(Sighting.page_id.in_(page_ids), Indicator.ioc_type.in_(("btc", "eth", "xmr", "telegram", "jabber")))
             .distinct().limit(50))
        wallets = [{"type": i.ioc_type, "value": i.value, "indicator_id": i.id} for i in q]
    weeks = Counter()
    cutoff = utcnow() - timedelta(weeks=26)
    for x in sights:
        if x.ts and x.ts >= cutoff:
            weeks[x.ts.strftime("%G-W%V")] += 1
    risk = max([a.risk_score or 0 for a in alerts] + [0])
    risk = min(100.0, risk + min(15.0, 2.0 * len(orgs)) + min(10.0, 0.5 * len(sights)))
    actor.risk_score = round(risk, 1)
    profile = {
        "venues": [{"host": h, "mentions": n} for h, n in hosts.most_common(15)],
        "targets": [{"organization": o, "alerts": n} for o, n in orgs.most_common(15)],
        "threat_classes": dict(classes),
        "linked_indicators": wallets,
        "activity": [{"week": w, "mentions": n} for w, n in sorted(weeks.items())],
        "alerts": [{"id": a.id, "title": a.title, "severity": a.severity, "threat_class": a.threat_class,
                    "risk_score": a.risk_score} for a in alerts[-25:]],
        "summary": _summary(actor, hosts, orgs, classes),
        "built_at": utcnow().isoformat() + "Z",
    }
    actor.profile = profile
    return profile


def _summary(actor: ThreatActor, hosts: Counter, orgs: Counter, classes: Counter) -> str:
    kind = actor.kind.replace("_", " ")
    parts = [f"{actor.name} ({kind}) has {actor.mention_count or 0} recorded mention(s)"]
    if hosts:
        parts.append(f"active on {len(hosts)} site(s), mostly {hosts.most_common(1)[0][0]}")
    if orgs:
        parts.append("associated with findings about " + ", ".join(o for o, _ in orgs.most_common(3)))
    if classes:
        parts.append("activity type: " + ", ".join(c.replace("_", " ") for c, _ in classes.most_common(3)))
    return "; ".join(parts) + "."


def actor_dict(s, a: ThreatActor, full: bool = False) -> dict:
    d = {"id": a.id, "name": a.name, "kind": a.kind, "aliases": a.aliases or [], "tags": a.tags or [],
         "description": a.description, "mention_count": a.mention_count, "risk_score": a.risk_score,
         "first_seen": a.first_seen.isoformat() + "Z" if a.first_seen else None,
         "last_seen": a.last_seen.isoformat() + "Z" if a.last_seen else None}
    if full:
        d["handles"] = [{"id": h.id, "platform": h.platform, "value": h.value,
                         "first_seen": h.first_seen.isoformat() + "Z" if h.first_seen else None,
                         "last_seen": h.last_seen.isoformat() + "Z" if h.last_seen else None}
                        for h in s.query(ActorHandle).filter_by(actor_id=a.id).order_by(ActorHandle.platform)]
        d["profile"] = a.profile or {}
        d["recent"] = [{"ts": x.ts.isoformat() + "Z" if x.ts else None, "source": x.source, "host": x.host,
                        "alert_id": x.alert_id, "page_id": x.page_id, "context": x.context[:300]}
                       for x in s.query(ActorSighting).filter_by(actor_id=a.id)
                       .order_by(ActorSighting.ts.desc()).limit(20)]
    return d
