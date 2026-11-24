"""Smart query suggestions and recommendations built from the current data.

Rule-based and instant; with ``use_ai`` a model proposes extra questions from a
compact, masked statistics summary (never raw page content)."""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import func

from ..storage.db import session_scope
from ..storage.models import SEVERITY_RANK, Alert, CrawlRun, Target, utcnow
from ..storage.models_intel import Organization, OrgAsset, ThreatActor

logger = logging.getLogger(__name__)
HELP_QUESTIONS = [
    "How do I connect Tor through a bridge if Tor is blocked?",
    "How should I set up my organisation step by step?",
    "What is the difference between Standard, Smart and Agent crawl modes?",
    "How do I export evidence for a legal case?",
]


def _q(label: str, prompt: str, why: str, kind: str = "analyst") -> dict:
    return {"label": label, "prompt": prompt, "why": why, "kind": kind}


def _facts(s) -> dict:
    now = utcnow()
    day = now - timedelta(hours=24)
    week = now - timedelta(days=7)
    open_alerts = s.query(Alert).filter(Alert.status.in_(("new", "acknowledged")))
    return {
        "now": now,
        "new_24h": s.query(func.count(Alert.id)).filter(Alert.created_at >= day).scalar() or 0,
        "hot": [a for a in open_alerts.order_by(Alert.risk_score.desc(), Alert.id.desc()).limit(50)
                if SEVERITY_RANK.get(a.severity, 0) >= SEVERITY_RANK["high"]],
        "unreviewed": open_alerts.filter(Alert.status == "new", Alert.analyst_session_id.is_(None)).count(),
        "orgs": s.query(Organization).order_by(Organization.risk_score.desc()).limit(5).all(),
        "orgs_no_assets": [o.name for o in s.query(Organization).all()
                           if not s.query(OrgAsset).filter_by(org_id=o.id).count()][:5],
        "actors": s.query(ThreatActor).order_by(ThreatActor.risk_score.desc(), ThreatActor.last_seen.desc()).limit(3).all(),
        "classes": dict(s.query(Alert.threat_class, func.count(Alert.id)).filter(Alert.created_at >= week,
                                                                                 Alert.threat_class != "")
                        .group_by(Alert.threat_class).all()),
        "fp": s.query(func.count(Alert.id)).filter(Alert.status == "false_positive", Alert.created_at >= week).scalar() or 0,
        "failed_runs": s.query(func.count(CrawlRun.id)).filter(CrawlRun.status == "failed",
                                                              CrawlRun.started_at >= day).scalar() or 0,
        "down_targets": s.query(func.count(Target.id)).filter(Target.active.is_(True), Target.last_status == "down").scalar() or 0,
        "unscheduled": s.query(func.count(Target.id)).filter(
            Target.active.is_(True), Target.approval == "approved",
            (Target.schedule_interval_min.is_(None)) | (Target.schedule_interval_min == 0),
            (Target.schedule_cron.is_(None)) | (Target.schedule_cron == "")).scalar() or 0,
    }


def queries(f: dict) -> list[dict]:
    out = []
    if f["hot"]:
        a = f["hot"][0]
        out.append(_q(f"Investigate the riskiest open alert #{a.id}",
                      f"Investigate alert #{a.id}: is it a real threat, which organisation is affected and what should we do first?",
                      f"risk {int(a.risk_score or 0)}, {a.severity}"))
    if f["new_24h"]:
        out.append(_q(f"Summarise the {f['new_24h']} alert(s) of the last 24 h",
                      "Summarise the alerts of the last 24 hours: group them by organisation and threat class, "
                      "name the three that need action first and why.", "new activity"))
    for o in f["orgs"][:2]:
        if (o.risk_score or 0) > 0:
            out.append(_q(f"Why is {o.name} at risk {int(o.risk_score)}?",
                          f"Explain the risk score of organisation '{o.name}': which alerts and factors drive it and "
                          "what would lower it fastest?", f"risk level {o.risk_level}"))
    if f["classes"].get("credential_leak"):
        out.append(_q("Which of our accounts appear in credential leaks?",
                      "List the organisation accounts that appeared in credential leaks this week (passwords are masked), "
                      "where they were seen and which to reset first.", f"{f['classes']['credential_leak']} leak alert(s) this week"))
    if f["classes"].get("ransomware"):
        out.append(_q("Are we named on a ransomware leak site?",
                      "Check the ransomware alerts of this week: is any of our organisations or suppliers named, "
                      "which group posted it and what is the deadline?", "ransomware alerts this week"))
    if f["classes"].get("initial_access"):
        out.append(_q("Is someone selling access to our network?",
                      "Review this week's initial-access-broker alerts: do they match our sector, size or domains?",
                      "initial access sales seen"))
    for act in f["actors"][:1]:
        out.append(_q(f"Profile threat actor {act.name}",
                      f"What do we know about threat actor '{act.name}': handles, contacts, which of our assets they "
                      "mentioned, and how active they are?", "most relevant actor"))
    if f["fp"] >= 3:
        out.append(_q("Which watch terms cause false positives?",
                      "Which watch terms produced the most false positives this week, and what suppression rule "
                      "or term change would you suggest?", f"{f['fp']} false positives this week"))
    out.append(_q("Which indicators were seen on several sites?",
                  "Which indicators (IPs, domains, wallets, e-mails) were seen on more than one site recently, and are "
                  "any of them on our watchlist?", "cross-site correlation"))
    out += [_q(h, h, "how-to", kind="help") for h in HELP_QUESTIONS[:2]]
    return out[:10]


def recommendations(f: dict) -> list[dict]:
    from ..readiness import checklist
    out = []
    for st in checklist():
        if not st["done"] and not st.get("optional"):
            out.append({"level": "high" if st["next"] else "medium", "text": f"{st['title']}: {st['detail']}",
                        "action": st["action"]})
    ai = next((st for st in checklist() if st["id"] == "ai"), None)
    if ai and not ai["done"]:
        out.append({"level": "medium", "text": "No local AI model - analysis is rule-based. Set up the built-in AI "
                    "engine for better triage and the analyst.", "action": ai["action"]})
    if f["unreviewed"] >= 5:
        out.append({"level": "medium", "text": f"{f['unreviewed']} new alerts have not been reviewed. Let the AI analyst "
                    "triage them or lower ANALYST_AUTO_SEVERITY.", "action": {"label": "Alerts", "view": "alerts"}})
    if f["orgs_no_assets"]:
        out.append({"level": "medium", "text": "Organisations without assets never receive alerts: "
                    + ", ".join(f["orgs_no_assets"]), "action": {"label": "Organizations", "view": "orgs"}})
    if f["failed_runs"]:
        out.append({"level": "medium", "text": f"{f['failed_runs']} crawl(s) failed in the last 24 h - check Runs; "
                    "if Tor was the cause, use Reconnect.", "action": {"label": "Runs", "view": "runs"}})
    if f["down_targets"]:
        out.append({"level": "low", "text": f"{f['down_targets']} target(s) are down - onion services move often; "
                    "consider disabling or replacing them.", "action": {"label": "Targets", "view": "targets"}})
    if f["unscheduled"]:
        out.append({"level": "low", "text": f"{f['unscheduled']} target(s) have no schedule and are only crawled by hand.",
                    "action": {"label": "Targets", "view": "targets"}})
    return out[:10]


def _ai_queries(f: dict, existing: list[dict]) -> list[dict]:
    from ..ai.router import get_router
    providers = get_router().providers_for("run_summary")
    if not providers:
        return []
    summary = {"alerts_24h": f["new_24h"], "open_high": len(f["hot"]), "threat_classes_week": f["classes"],
               "organisations": [{"name": o.name, "risk": int(o.risk_score or 0)} for o in f["orgs"]],
               "actors": [a.name for a in f["actors"]], "false_positives_week": f["fp"]}
    prompt = ("You help a SOC analyst using a dark-web monitoring platform. From these statistics propose up to 4 "
              "concrete investigation questions the analyst should ask next. Do not repeat: "
              + "; ".join(q["label"] for q in existing) + f"\nStatistics: {summary}\n"
              'Answer as JSON, e.g. {"questions": [{"label": "Leaked admin accounts of acme.com", '
              '"prompt": "Which admin accounts of acme.com appeared in leaks this week and where?", '
              '"why": "credential leaks rose this week"}]}')
    for p in providers:
        try:
            res = p.chat_json(prompt, system="Answer only with JSON.")
            items = res.get("questions") if isinstance(res, dict) else None
            return [_q(_label(i), str(i["prompt"])[:600], str(i.get("why") or "AI")[:120])
                    for i in (items or []) if isinstance(i, dict) and len(str(i.get("prompt") or "")) > 10][:4]
        except Exception as e:  # noqa: BLE001
            logger.info("AI query suggestions failed on %s: %s", getattr(p, "name", "?"), e)
    return []


def _label(item: dict) -> str:
    """Small models sometimes echo the template ("short"); fall back to the question."""
    label = str(item.get("label") or "").strip()
    if len(label) < 8 or label.lower() in ("short", "label", "short label"):
        label = str(item.get("prompt") or "").strip()
    return label if len(label) <= 90 else label[:87].rstrip() + "…"


def suggestions(use_ai: bool = False) -> dict:
    with session_scope() as s:
        f = _facts(s)
        qs = queries(f)
        recs = recommendations(f)
        ai = []
        if use_ai:
            ai = _ai_queries(f, qs)
        for q in ai:
            q["ai"] = True
    return {"queries": ai + qs, "recommendations": recs, "ai_used": bool(ai)}
