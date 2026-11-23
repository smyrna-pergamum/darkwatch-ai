"""Crawl frontiers: which URL to visit next.

* BFSFrontier    - classic breadth-first (standard mode)
* SmartFrontier  - priority queue ranked by relevance to the watchlist /
                   goal, optionally re-scored in batches by the AI (smart mode)
The agent frontier lives in ``darkweb_monitor.ai.agent``.
"""
from __future__ import annotations

import heapq
import itertools
import re
from collections import deque
from typing import Callable, Iterable, Optional

# Generic threat-intel vocabulary that makes a link more interesting.
INTEREST_TERMS = {
    "leak": 3, "leaks": 3, "dump": 3, "database": 2, "db": 1, "breach": 3, "combo": 2,
    "credential": 3, "login": 1, "password": 2, "ransom": 3, "victim": 3, "blog": 1,
    "press": 1, "release": 1, "sale": 1, "sell": 2, "access": 2, "rdp": 2, "vpn": 2,
    "exploit": 2, "0day": 3, "cve": 2, "forum": 1, "thread": 1, "topic": 1, "post": 1,
    "market": 1, "shop": 1, "stealer": 3, "logs": 2, "botnet": 2, "malware": 2,
}
BORING_TERMS = {"faq", "rules", "register", "signup", "terms", "privacy", "contact", "about",
                "help", "captcha", "logout", "lang", "language", "rss", "theme"}

_TOKEN = re.compile(r"[a-z0-9]+")


def heuristic_score(url: str, text: str, focus_terms: Iterable[str] = ()) -> float:
    blob = f"{url} {text}".lower()
    toks = set(_TOKEN.findall(blob))
    score = 0.0
    for t in focus_terms:
        t = t.lower().strip()
        if t and t in blob:
            score += 6.0
    score += sum(w for k, w in INTEREST_TERMS.items() if k in toks)
    score -= 2.0 * len(toks & BORING_TERMS)
    if "page=" in blob or "start=" in blob:
        score += 0.5  # pagination often hides new posts
    return score


class BFSFrontier:
    mode = "standard"

    def __init__(self):
        self._q: deque = deque()

    def push(self, url: str, depth: int, text: str = "", parent: str = "") -> None:
        self._q.append((url, depth))

    def pop(self) -> Optional[tuple[str, int]]:
        return self._q.popleft() if self._q else None

    def __len__(self) -> int:
        return len(self._q)

    def observe(self, page: dict) -> None:  # noqa: D401 - hook for subclasses
        pass

    def stop_reason(self) -> Optional[str]:
        return None


class SmartFrontier(BFSFrontier):
    """Best-first frontier. ``ai_scorer`` receives [{url,text}] and returns
    {url: score 0..10}; it is called in batches and merged with the heuristic."""

    mode = "smart"

    def __init__(self, focus_terms: Iterable[str] = (), ai_scorer: Callable | None = None,
                 batch: int = 40):
        super().__init__()
        self.focus = [t for t in focus_terms if t]
        self.ai_scorer = ai_scorer
        self.batch = batch
        self._heap: list = []
        self._pending: list[dict] = []
        self._counter = itertools.count()
        self.scores: dict[str, float] = {}

    def push(self, url: str, depth: int, text: str = "", parent: str = "") -> None:
        h = heuristic_score(url, text, self.focus)
        self.scores[url] = h
        if self.ai_scorer:
            self._pending.append({"url": url, "text": text, "depth": depth, "h": h})
            if len(self._pending) >= self.batch:
                self._flush()
        else:
            self._heap_push(url, depth, h)

    def _heap_push(self, url: str, depth: int, score: float) -> None:
        # deeper pages get a small penalty so we do not tunnel forever
        heapq.heappush(self._heap, (-(score - 0.5 * depth), next(self._counter), url, depth))

    def _flush(self) -> None:
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        ai_scores = {}
        try:
            ai_scores = self.ai_scorer([{"url": b["url"], "text": b["text"]} for b in batch]) or {}
        except Exception:  # noqa: BLE001 - AI is best effort
            ai_scores = {}
        for b in batch:
            s = b["h"] + 1.5 * float(ai_scores.get(b["url"], 0) or 0)
            self.scores[b["url"]] = s
            self._heap_push(b["url"], b["depth"], s)

    def pop(self) -> Optional[tuple[str, int]]:
        if not self._heap:
            self._flush()
        if not self._heap:
            return None
        _, _, url, depth = heapq.heappop(self._heap)
        return url, depth

    def __len__(self) -> int:
        return len(self._heap) + len(self._pending)
