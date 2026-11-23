"""End-to-end crawl pipeline."""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

from config.settings import settings
from .storage.db import session_scope
from .storage.models import Target, Page, IOC, Alert, CrawlRun
from .crawler.spider import Spider
from .ioc.extractor import extract as extract_ioc, content_hash
from .ai.router import AIRouter
from .alerts.notifier import Notifier

logger = logging.getLogger(__name__)

ai = AIRouter()
notifier = Notifier()


def _get_or_create_target(session, url: str, keywords: str = "") -> Target:
    t = session.query(Target).filter_by(url=url).first()
    if not t:
        t = Target(url=url, keywords=keywords)
        session.add(t)
        session.flush()
    return t


def run_crawl(start_url: str, keywords: str = "", depth: int = None) -> dict:
    run = None
    with session_scope() as s:
        run = CrawlRun()
        s.add(run)
        s.flush()
        run_id = run.id

    target_url = start_url
    target_keywords = [k.strip() for k in (keywords or "").split(",") if k.strip()]

    pages_crawled = 0
    iocs_found = 0
    alerts_raised = 0
    run_pages = []          # page-level analyses from this run
    run_alerts = []         # {"severity", "title"} from this run
    run_ioc_types = {}      # type -> count
    run_keywords = set()

    def on_page(page: dict):
        nonlocal pages_crawled, iocs_found, alerts_raised
        if page.get("error"):
            logger.warning("page error %s: %s", page["url"], page["error"])
            return
        text = page.get("text", "") or ""
        h = content_hash(text)
        with session_scope() as s:
            target = _get_or_create_target(s, target_url, keywords)
            target.last_crawled = __import__("datetime").datetime.utcnow()
            # skip unchanged content
            existing = s.query(Page).filter_by(url=page["url"], content_hash=h).first()
            if existing and existing.ai_summary and existing.ai_summary not in ("None", "null"):
                logger.info("unchanged, skipping AI: %s", page["url"])
                pages_crawled += 1
                return
            if existing:
                logger.info("re-analyzing (no prior summary): %s", page["url"])
                # remove stale page to avoid duplicates
                s.delete(existing)
                s.flush()
            p = Page(
                target_id=target.id,
                url=page["url"],
                title=page.get("title", ""),
                content=text[:20000],
                content_hash=h,
                status_code=page.get("status_code"),
                depth=page.get("depth", 0),
            )
            s.add(p)
            s.flush()

            # keyword watch
            matched_kw = [k for k in target_keywords if k.lower() in text.lower()]
            # regex IOC
            iocs = extract_ioc(text)
            for i in iocs:
                s.add(IOC(page_id=p.id, ioc_type=i["ioc_type"], value=i["value"], context=i["context"]))
                run_ioc_types[i["ioc_type"]] = run_ioc_types.get(i["ioc_type"], 0) + 1
            iocs_found += len(iocs)

            # AI analysis
            try:
                analysis = ai.analyze_page(page["url"], page.get("title", ""), text)
            except Exception as e:
                analysis = {"summary": f"ai error: {e}", "category": "unknown", "severity": "low", "keywords_found": [], "ioc_hints": []}
            p.ai_summary = analysis.get("summary", "")
            p.ai_severity = analysis.get("severity", "low")
            run_pages.append({
                "url": p.url,
                "title": p.title,
                "severity": p.ai_severity,
                "summary": p.ai_summary,
            })
            run_keywords.update(matched_kw)
            # AI IOC extraction (merge)
            try:
                ai_iocs = ai.extract_ioc_ai(text)
                for ai_i in ai_iocs:
                    it = ai_i.get("type", "other")
                    s.add(IOC(page_id=p.id, ioc_type=it,
                              value=ai_i.get("value", ""), context="ai-extracted",
                              confidence=float(ai_i.get("confidence", 0.5))))
                    iocs_found += 1
                    run_ioc_types[it] = run_ioc_types.get(it, 0) + 1
            except Exception:
                pass

            severity = p.ai_severity or "low"
            # escalate if keywords matched or high severity
            if matched_kw or severity in ("high", "critical"):
                title = f"Dark web hit: {page.get('title') or page['url']}"
                desc = (analysis.get("summary") or "") + f"\nMatched keywords: {matched_kw}"
                notifier.notify(title, desc, severity=severity, iocs=[i["value"] for i in iocs], url=page["url"])
                s.add(Alert(page_id=p.id, severity=severity, title=title, description=desc, notified=True))
                alerts_raised += 1
                run_alerts.append({"severity": severity, "title": title})
            pages_crawled += 1

    spider = Spider(on_page=on_page)
    spider.crawl(start_url, depth=depth)

    # Post-crawl: run-level AI summary
    try:
        run_ai = ai.summarize_run(
            start_url,
            run_pages,
            iocs_found=iocs_found,
            alerts_raised=alerts_raised,
            alerts=run_alerts,
            ioc_types=run_ioc_types,
            keywords=sorted(run_keywords),
        )
    except Exception as e:
        logger.exception("run summary failed")
        run_ai = {"summary": f"ai error: {e}", "risk_level": "low",
                  "key_findings": [], "recommendations": []}

    with session_scope() as s:
        r = s.query(CrawlRun).filter_by(id=run_id).first()
        if r:
            r.finished_at = __import__("datetime").datetime.utcnow()
            r.pages_crawled = pages_crawled
            r.iocs_found = iocs_found
            r.alerts_raised = alerts_raised
            r.status = "done"
            r.ai_summary = json.dumps(run_ai, ensure_ascii=False)

    return {
        "run_id": run_id,
        "pages_crawled": pages_crawled,
        "iocs_found": iocs_found,
        "alerts_raised": alerts_raised,
        "ai_summary": run_ai,
    }