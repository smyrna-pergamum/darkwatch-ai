"""Crawl orchestrator: fetch -> parse -> safety filter -> callback -> frontier."""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict

from config.settings import settings
from .frontier import BFSFrontier
from .parsers import host_of, in_scope, normalize_url, parse_page, safety_violation
from .tor_client import TorClient

logger = logging.getLogger(__name__)


class CrawlCancelled(Exception):
    pass


class Spider:
    """Passive, GET-only crawler. Never submits forms or logs in."""

    def __init__(self, on_page: Callable[[Dict[str, Any]], None] | None = None,
                 frontier=None, client: TorClient | None = None,
                 should_stop: Callable[[], bool] | None = None,
                 scope: str | None = None, delay: float | None = None):
        self.client = client or TorClient()
        self.on_page = on_page
        self.frontier = frontier if frontier is not None else BFSFrontier()
        self.should_stop = should_stop or (lambda: False)
        self.scope = scope
        self.delay = settings.CRAWL_DELAY_SEC if delay is None else delay
        self.visited: set[str] = set()
        self.blocked_hosts: set[str] = set()
        self.stats = {"fetched": 0, "errors": 0, "skipped": 0, "blocked": 0,
                      "start_status": None, "stop_reason": None}

    def crawl(self, start_url: str, depth: int | None = None,
              max_pages: int | None = None) -> dict:
        depth = settings.CRAWL_DEPTH if depth is None else depth
        max_pages = settings.CRAWL_MAX_PAGES if max_pages is None else max_pages
        start_url = normalize_url(start_url)
        self.visited.add(start_url)
        self.frontier.push(start_url, 0, "start", "")
        first = True
        while self.stats["fetched"] < max_pages:
            if self.should_stop():
                self.stats["stop_reason"] = "cancelled"
                raise CrawlCancelled()
            reason = self.frontier.stop_reason()
            if reason:
                self.stats["stop_reason"] = reason
                break
            nxt = self.frontier.pop()
            if nxt is None:
                self.stats["stop_reason"] = self.frontier.stop_reason() or "frontier exhausted"
                break
            url, d = nxt
            if host_of(url) in self.blocked_hosts:
                continue
            if not first and self.delay:
                time.sleep(self.delay)
            logger.info("crawl d=%d %s", d, url)
            res = self.client.get(url)
            if first:
                self.stats["start_status"] = "up" if res.ok else "down"
                self.stats["start_error"] = res.error
                first = False
            if not res.ok:
                if res.error and res.error.startswith("skipped"):
                    self.stats["skipped"] += 1
                else:
                    self.stats["errors"] += 1
                self.frontier.observe({"url": url, "error": res.error, "depth": d})
                continue
            parsed = parse_page(res.text, res.final_url or url)
            hit = safety_violation(parsed["title"] + "\n" + parsed["text"])
            if hit:
                # discard immediately - nothing stored, nothing sent to AI
                host = host_of(url)
                self.blocked_hosts.add(host)
                self.stats["blocked"] += 1
                logger.warning("SAFETY: discarded page and blocked host %s (matched blocklist)", host)
                self.frontier.observe({"url": url, "error": "safety-block", "depth": d})
                continue
            self.stats["fetched"] += 1
            page = {
                "url": url, "final_url": res.final_url, "title": parsed["title"],
                "text": parsed["text"], "links": parsed["links"],
                "meta_description": parsed["meta_description"],
                "status_code": res.status_code, "depth": d, "truncated": res.truncated,
                "html": res.text if settings.FORUM_PARSING else "",
            }
            if self.on_page:
                try:
                    self.on_page(page)
                except CrawlCancelled:
                    raise
                except Exception:  # noqa: BLE001
                    logger.exception("on_page callback error for %s", url)
            self.frontier.observe(page)
            if d < depth:
                for link in parsed["links"]:
                    lu = link["url"]
                    if lu in self.visited or host_of(lu) in self.blocked_hosts:
                        continue
                    if not in_scope(lu, start_url, self.scope):
                        continue
                    self.visited.add(lu)
                    self.frontier.push(lu, d + 1, link.get("text", ""), url)
        else:
            self.stats["stop_reason"] = "max pages reached"
        return self.stats
