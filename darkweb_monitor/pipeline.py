"""End-to-end crawl pipeline for one run.

fetch (spider) -> mask secrets -> change detection -> regex IOCs -> watchlist
-> local AI analysis -> indicators/sightings -> deduplicated alerts (+ triage,
notify) -> run summary -> follow-up task planning.
"""
from __future__ import annotations

import json
import logging
from typing import Callable, Optional

from config.settings import settings
from .ai.agent import AgentFrontier
from .ai.base import AIError
from .ai.router import get_router
from .alerts.service import dedup_key, raise_alert
from .crawler.forum import parse_forum
from .crawler.frontier import BFSFrontier, SmartFrontier
from .crawler.parsers import host_of, is_onion, is_valid_onion_v3, normalize_url
from .crawler.spider import CrawlCancelled, Spider
from .crawler.tor_client import TorUnavailable, ensure_tor, new_identity
from .intel.changes import diff_summary
from .ioc.extractor import content_hash, extract as extract_ioc, mask_credentials
from .learning.rules import apply as apply_rules
from .sources.feeds import feed_tags_for
from .storage.db import audit, session_scope
from .storage.models import (
    SEVERITY_RANK, CrawlRun, Indicator, Page, Sighting, Target, WatchItem, max_severity, utcnow,
)
from .watchlist import WatchTerm, match as watch_match

logger = logging.getLogger(__name__)

AI_IOC_TYPES = {"ip", "email", "hash", "url", "domain", "onion", "crypto", "cve", "handle", "other"}


def _get_or_create_target(s, url: str, keywords: str = "") -> Target:
    url = normalize_url(url)
    t = s.query(Target).filter_by(url=url).first()
    if not t:
        t = Target(url=url, keywords=keywords)
        s.add(t)
        s.flush()
    return t


def load_watch_terms(s, target: Target | None) -> list[WatchTerm]:
    terms = [WatchTerm(w.kind, w.value, w.severity, w.id)
             for w in s.query(WatchItem).filter_by(active=True).all()]
    if target and target.keywords:
        for k in target.keywords.split(","):
            if k.strip():
                terms.append(WatchTerm("keyword", k.strip(), "medium", None))
    return terms


def _upsert_indicator(s, ioc_type: str, value: str, conf: float, page_id: int, run_id: int,
                      context: str, source: str, watch_values: set[str]) -> None:
    value = value.strip()[:500]
    if not value:
        return
    ind = s.query(Indicator).filter_by(ioc_type=ioc_type, value=value).first()
    now = utcnow()
    if not ind:
        ind = Indicator(ioc_type=ioc_type, value=value, first_seen=now, last_seen=now,
                        seen_count=0, confidence=conf)
        tags = feed_tags_for(s, ioc_type.split(":", 1)[-1], value)
        if tags:
            ind.tags = ",".join(sorted(set(tags)))
        s.add(ind)
        s.flush()
    ind.last_seen = now
    ind.seen_count = (ind.seen_count or 0) + 1
    ind.confidence = max(ind.confidence or 0, conf)
    low = value.lower()
    if any(w in low for w in watch_values):
        ind.on_watchlist = True
    s.add(Sighting(indicator_id=ind.id, page_id=page_id, run_id=run_id,
                   context=context[:500], source=source, confidence=conf))


def heuristic_run_summary(start_url: str, pages: list, alerts: list, iocs_found: int,
                          ioc_types: dict, keywords: list, changed: int) -> dict:
    risk = max_severity(*(a["severity"] for a in alerts)) if alerts else "low"
    findings = [f"{len(alerts)} alert(s); highest severity {risk}"] if alerts else []
    if keywords:
        findings.append("Watchlist hits: " + ", ".join(keywords[:10]))
    if ioc_types:
        findings.append("Indicators: " + ", ".join(f"{k}={v}" for k, v in sorted(ioc_types.items())))
    recs = []
    if risk in ("high", "critical"):
        recs.append("Review the alerted pages and validate exposure of the matched assets.")
        recs.append("Rotate any credentials or keys that appear in matched content.")
    if not alerts:
        recs.append("No action needed; keep the scheduled monitoring running.")
    return {
        "summary": (f"Crawled {len(pages)} page(s) from {start_url} ({changed} new/changed), "
                    f"extracted {iocs_found} indicator(s) and raised {len(alerts)} alert(s). "
                    "AI was unavailable, so this summary is rule-based."),
        "risk_level": risk, "key_findings": findings, "recommendations": recs, "provider": "rules",
    }


def _profile_forum_authors(s, page: dict, page_id: int, alert, terms: list[str]) -> None:
    """Forum monitoring: attribute posts that mention watched assets to actors."""
    if not (settings.FORUM_PARSING and settings.ACTOR_PROFILING and page.get("html")):
        return
    try:
        posts = parse_forum(page["html"])
        if not posts:
            return
        from .intel.actors import ingest_forum_posts
        from .intel.hooks import after_actor_link
        with s.begin_nested():  # a race on a new nickname only rolls back the profiling
            ids = ingest_forum_posts(s, posts, host=host_of(page["url"]), page_id=page_id,
                                     watch_terms=terms, alert_id=alert.id)
        if ids:
            after_actor_link(s, alert)
    except Exception:  # noqa: BLE001 - profiling never breaks the crawl
        logger.exception("forum profiling failed for %s", page.get("url"))


def run_crawl(start_url: str | None = None, keywords: str = "", depth: int | None = None,
              *, target_id: int | None = None, run_id: int | None = None,
              mode: str | None = None, goal: str | None = None, max_pages: int | None = None,
              trigger: str = "manual", should_stop: Optional[Callable[[], bool]] = None,
              spider_client=None) -> dict:
    router = get_router()

    # ---- resolve target / run ----------------------------------------------
    with session_scope() as s:
        if target_id:
            target = s.get(Target, target_id)
            if not target:
                raise ValueError(f"target {target_id} not found")
        else:
            if not start_url:
                raise ValueError("start_url or target_id required")
            target = _get_or_create_target(s, start_url, keywords)
            if keywords and keywords != target.keywords:
                target.keywords = keywords
        if target.approval != "approved":
            raise ValueError("target is pending approval")
        start_url = target.url
        mode = mode or target.crawl_mode or "standard"
        goal = goal if goal is not None else (target.agent_goal or "")
        depth = depth if depth is not None else target.depth
        max_pages = max_pages if max_pages is not None else target.max_pages
        scope = target.scope
        tid = target.id
        schedule = (f"every {target.schedule_interval_min} min" if target.schedule_interval_min
                    else target.schedule_cron or "manual")
        terms = load_watch_terms(s, target)
        if run_id:
            run = s.get(CrawlRun, run_id)
        else:
            run = CrawlRun(target_id=tid, start_url=start_url, mode=mode, trigger=trigger)
            s.add(run)
            s.flush()
        run.status, run.started_at, run.mode, run.target_id, run.start_url = "running", utcnow(), mode, tid, start_url
        run_id = run.id

    watch_values = {t.value.lower().lstrip("@") for t in terms if t.kind in ("email", "ip", "crypto", "domain")}
    watch_labels = [t.value for t in terms]

    st = {"pages": 0, "changed": 0, "iocs": 0, "alerts": 0}
    run_pages: list[dict] = []
    run_alerts: list[dict] = []
    ioc_types: dict[str, int] = {}
    hit_terms: set[str] = set()
    discovered: set[str] = set()
    discovered_from_hits: set[str] = set()
    start_host = host_of(start_url)
    ai_page_ok = router.available("page")

    def on_page(page: dict) -> None:
        text = mask_credentials(page.get("text", "") or "")
        title = page.get("title", "") or ""
        h = content_hash(text)
        url = page["url"]
        for lk in page.get("links", []):
            hh = host_of(lk["url"])
            if hh and hh != start_host and is_onion(lk["url"]) and is_valid_onion_v3(hh):
                discovered.add(f"http://{hh}/")
        with session_scope() as s:
            p = s.query(Page).filter_by(url=url).order_by(Page.id.desc()).first()
            unchanged = bool(p and p.content_hash == h)
            old_content = (p.content or "") if (p is not None and not unchanged and not p.content_purged) else ""
            if p is None:
                p = Page(target_id=tid, url=url, first_seen=utcnow())
                s.add(p)
            p.previous_hash = p.content_hash or ""
            p.changed = not unchanged
            p.content_hash, p.run_id, p.target_id = h, run_id, tid
            p.title, p.status_code, p.depth, p.crawled_at = title[:500], page.get("status_code"), page.get("depth", 0), utcnow()
            if old_content:
                p.change_summary = diff_summary(old_content, text, watch_labels)
            if settings.STORE_PAGE_CONTENT:
                p.content, p.content_purged = text[: settings.MAX_STORED_CONTENT_CHARS], False
            s.flush()
            st["pages"] += 1
            if unchanged and (p.ai_analyzed or not ai_page_ok):
                page["analysis"] = {"summary": p.ai_summary or ""}
                run_pages.append({"url": url, "title": p.title, "severity": p.ai_severity,
                                  "summary": p.ai_summary, "changed": False})
                return
            if not unchanged:
                st["changed"] += 1

            # regex IOCs + watchlist
            iocs = extract_ioc(title + "\n" + text)
            matches = watch_match(title + "\n" + text, terms)
            raw_matches = len(matches)
            matches, rules_applied = apply_rules(matches, title + "\n" + text, url, session=s)
            for m in matches:
                hit_terms.add(m["value"])
            if matches:
                discovered_from_hits.update(
                    f"http://{host_of(lk['url'])}/" for lk in page.get("links", [])
                    if is_onion(lk["url"]) and host_of(lk["url"]) != start_host
                    and is_valid_onion_v3(host_of(lk["url"])))

            # AI analysis (local / privacy-routed)
            analysis = None
            if ai_page_ok:
                try:
                    analysis = router.analyze_page(url, title, text, watch_labels)
                except AIError as e:
                    logger.info("page AI failed for %s: %s", url, e)
            if analysis:
                p.ai_summary, p.ai_severity = analysis["summary"], analysis["severity"]
                p.ai_category, p.ai_analyzed = analysis["category"], True
            else:
                p.ai_summary = p.ai_summary if unchanged else (page.get("meta_description") or "")[:500]
                p.ai_severity = max_severity(*(m["severity"] for m in matches)) if matches else "low"
                p.ai_analyzed = False
            page["analysis"] = analysis or {"summary": p.ai_summary}

            for i in iocs:
                _upsert_indicator(s, i["ioc_type"], i["value"], i["confidence"], p.id, run_id,
                                  i["context"], "regex", watch_values)
                ioc_types[i["ioc_type"]] = ioc_types.get(i["ioc_type"], 0) + 1
            st["iocs"] += len(iocs)
            regex_vals = {i["value"].lower() for i in iocs}
            for ai_i in (analysis or {}).get("iocs", []):
                it = str(ai_i.get("type", "other")).lower()
                it = it if it in AI_IOC_TYPES else "other"
                val = str(ai_i.get("value", "")).strip()
                if not val or val.lower() in regex_vals or len(val) > 500:
                    continue
                if val.lower() not in text.lower():
                    continue  # never store indicators the model hallucinated
                try:
                    conf = max(0.0, min(1.0, float(ai_i.get("confidence", 0.5))))
                except (TypeError, ValueError):
                    conf = 0.5
                _upsert_indicator(s, f"ai:{it}", val, conf, p.id, run_id, "ai-extracted", "ai", watch_values)
                ioc_types[f"ai:{it}"] = ioc_types.get(f"ai:{it}", 0) + 1
                st["iocs"] += 1

            severity = max_severity(p.ai_severity, *(m["severity"] for m in matches))
            run_pages.append({"url": url, "title": p.title, "severity": severity,
                              "summary": p.ai_summary, "changed": p.changed})
            if not matches and SEVERITY_RANK[severity] < SEVERITY_RANK["high"]:
                return
            if raw_matches and rules_applied and not matches and SEVERITY_RANK[p.ai_severity or "low"] < SEVERITY_RANK["high"]:
                return  # every watchlist hit was suppressed by an analyst-approved rule

            # ---- alert (deduplicated, triaged, notified) -------------------
            what = ", ".join(sorted({m["value"] for m in matches})[:5])
            title_txt = (f"Watchlist hit [{what}] on {title or url}" if matches
                         else f"{severity.title()} {p.ai_category or 'content'}: {title or url}")
            desc = (p.ai_summary or "").strip()
            if rules_applied:
                desc += "\n\nSuppression rules applied: " + ", ".join(
                    f"#{r['rule_id']} {r['action']} '{r['value']}'" for r in rules_applied)
            if matches:
                desc += "\n\nMatches:\n" + "\n".join(
                    f"- {m['kind']} '{m['value']}': …{m['context'][:160]}…" for m in matches[:8])
            basis = ",".join(sorted({f"{m['kind']}:{m['value'].lower()}" for m in matches})) or (p.ai_category or "")
            alert, created = raise_alert(
                s, source="crawler", key=dedup_key("crawler", url, basis), title=title_txt,
                description=desc, severity=severity, url=url, matches=matches,
                iocs=[i["value"] for i in iocs], page_id=p.id, target_id=tid, run_id=run_id,
                summary=p.ai_summary or "", router=router,
                context={"text": title + "\n" + text, "ioc_types": [i["ioc_type"] for i in iocs],
                         "ai_category": p.ai_category if p.ai_analyzed else ""})
            _profile_forum_authors(s, page, p.id, alert, [m["value"] for m in matches] or watch_labels)
            if created:
                st["alerts"] += 1
                run_alerts.append({"severity": severity, "title": title_txt[:500], "url": url})

    # ---- frontier ------------------------------------------------------------
    focus = watch_labels + ([goal] if goal else [])
    if mode == "agent":
        frontier = AgentFrontier(router, goal, watch_labels)
    elif mode == "smart":
        scorer = (lambda links: router.score_links(links, focus)) if router.available("link_score") else None
        frontier = SmartFrontier(focus, scorer, settings.SMART_SCORE_BATCH)
    else:
        frontier = BFSFrontier()

    status, error, spider_stats = "done", "", {}
    try:
        ensure_tor()
        if settings.TOR_NEWNYM_EVERY_RUN:
            new_identity()
        spider = Spider(on_page=on_page, frontier=frontier, client=spider_client,
                        should_stop=should_stop, scope=scope)
        spider_stats = spider.crawl(start_url, depth=depth, max_pages=max_pages)
    except CrawlCancelled:
        status, error = "cancelled", "cancelled by user"
    except TorUnavailable as e:
        status, error = "failed", str(e)
    except Exception as e:  # noqa: BLE001
        logger.exception("run %s failed", run_id)
        status, error = "failed", f"{type(e).__name__}: {e}"

    # ---- run summary ---------------------------------------------------------
    notes = getattr(frontier, "notes", [])
    run_ai = None
    if run_pages and router.available("run_summary"):
        try:
            run_ai = router.summarize_run(start_url, run_pages, st["iocs"], st["alerts"], run_alerts,
                                          ioc_types, sorted(hit_terms), mode, st["changed"], notes)
        except AIError as e:
            logger.info("run summary AI failed: %s", e)
    if run_ai is None:
        run_ai = heuristic_run_summary(start_url, run_pages, run_alerts, st["iocs"], ioc_types,
                                       sorted(hit_terms), st["changed"])
    if spider_stats.get("stop_reason"):
        run_ai["stop_reason"] = spider_stats["stop_reason"]

    with session_scope() as s:
        r = s.get(CrawlRun, run_id)
        r.finished_at, r.status, r.error = utcnow(), status, error[:2000]
        r.pages_crawled, r.pages_changed = st["pages"], st["changed"]
        r.iocs_found, r.alerts_raised = st["iocs"], st["alerts"]
        r.ai_summary = json.dumps(run_ai, ensure_ascii=False)
        r.agent_log = getattr(frontier, "log", [])
        r.notes = json.dumps({"spider": spider_stats, "discovered_onions": sorted(discovered)[:200]})
        t = s.get(Target, tid)
        if t:
            t.last_crawled = utcnow()
            if spider_stats.get("start_status"):
                t.last_status = spider_stats["start_status"]
                t.last_error = (spider_stats.get("start_error") or "")[:500]
            elif status == "failed":
                t.last_error = error[:500]

    # ---- follow-up tasks -----------------------------------------------------
    task_ids = []
    if status == "done":
        try:
            from .tasks import plan_after_run
            task_ids = plan_after_run(router, {
                "target_id": tid, "run_id": run_id, "start_url": start_url, "mode": mode,
                "schedule": schedule, "run_summary": run_ai, "alerts": run_alerts,
                "changed_pages": [p["url"] for p in run_pages if p.get("changed")],
                "discovered": sorted(discovered), "discovered_from_hits": sorted(discovered_from_hits),
                "watch": watch_labels})
        except Exception:  # noqa: BLE001
            logger.exception("task planning failed")

    audit("run.finish", f"run {run_id} {status} target={tid} pages={st['pages']} alerts={st['alerts']}")
    return {"run_id": run_id, "status": status, "error": error, "pages_crawled": st["pages"],
            "pages_changed": st["changed"], "iocs_found": st["iocs"], "alerts_raised": st["alerts"],
            "ai_summary": run_ai, "tasks_created": task_ids}
