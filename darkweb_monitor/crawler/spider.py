"""Crawl orchestrator."""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Callable, List, Dict, Any
from urllib.parse import urlparse

from config.settings import settings
from .tor_client import TorClient
from .parsers import parse_page, is_onion, same_domain

logger = logging.getLogger(__name__)


class Spider:
    def __init__(self, on_page: Callable[[Dict[str, Any]], None] = None):
        self.client = TorClient()
        self.on_page = on_page
        self.visited: set = set()

    def crawl(self, start_url: str, depth: int = None, max_pages: int = None) -> List[Dict[str, Any]]:
        depth = depth if depth is not None else settings.CRAWL_DEPTH
        max_pages = max_pages if max_pages is not None else settings.CRAWL_MAX_PAGES
        results: List[Dict[str, Any]] = []
        q = deque()
        q.append((start_url, 0))
        self.visited.add(start_url)
        while q and len(results) < max_pages:
            url, d = q.popleft()
            logger.info("Crawling %s (depth=%d)", url, d)
            resp, err = self.client.get(url)
            if err or resp is None:
                results.append({"url": url, "error": err, "depth": d})
                continue
            if resp.status_code != 200:
                results.append({"url": url, "status_code": resp.status_code, "depth": d, "error": f"HTTP {resp.status_code}"})
                continue
            parsed = parse_page(resp.text, url)
            page = {
                "url": url,
                "title": parsed["title"],
                "text": parsed["text"],
                "links": parsed["links"],
                "status_code": resp.status_code,
                "depth": d,
            }
            results.append(page)
            if self.on_page:
                try:
                    self.on_page(page)
                except Exception as e:
                    logger.exception("on_page callback error: %s", e)
            # enqueue links
            if d < depth:
                for link in parsed["links"]:
                    if link in self.visited:
                        continue
                    # only follow .onion or same domain by default
                    if not is_onion(link) and not same_domain(link, start_url):
                        continue
                    if settings.ALLOWED_DOMAINS:
                        allowed = [x.strip() for x in settings.ALLOWED_DOMAINS.split(",") if x.strip()]
                        host = urlparse(link).hostname or ""
                        if not any(host.endswith(a) for a in allowed):
                            continue
                    self.visited.add(link)
                    q.append((link, d + 1))
            time.sleep(settings.CRAWL_DELAY_SEC)
        return results