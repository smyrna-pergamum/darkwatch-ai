"""Agent crawl: an LLM decides, step by step, which in-scope link to open next
and when the goal is met. The agent can only choose among links the spider
already found in scope, can only issue GET requests (through the spider) and
falls back to the heuristic ranking when no AI is available."""
from __future__ import annotations

import logging
from typing import Optional

from config.settings import settings
from ..crawler.frontier import BFSFrontier, heuristic_score
from .base import AIError

logger = logging.getLogger(__name__)

_FORBIDDEN = ("login", "signin", "register", "signup", "checkout", "cart", "logout",
              "contact", "newthread", "reply", "post.php", "captcha", "deposit", "wallet")


class AgentFrontier(BFSFrontier):
    mode = "agent"

    def __init__(self, router, goal: str, watch: list[str] | None = None,
                 max_steps: int | None = None, n_candidates: int | None = None):
        super().__init__()
        self.router = router
        self.goal = goal or "Find content that threatens the watchlisted organisation"
        self.watch = watch or []
        self.max_steps = max_steps or settings.AGENT_MAX_STEPS
        self.n_candidates = n_candidates or settings.AGENT_CANDIDATES
        self.pool: dict[str, tuple[int, str]] = {}
        self.step = 0
        self.visited = 0
        self.notes: list[str] = []
        self.log: list[dict] = []
        self._stop: Optional[str] = None
        self._last: dict = {}
        self._start: Optional[tuple[str, int]] = None
        self._seeded = False

    # frontier API ----------------------------------------------------------
    def push(self, url: str, depth: int, text: str = "", parent: str = "") -> None:
        if not self._seeded:
            self._start, self._seeded = (url, depth), True
            return
        low = url.lower()
        if any(f in low for f in _FORBIDDEN):
            return
        if url not in self.pool:
            self.pool[url] = (depth, text)

    def __len__(self) -> int:
        return len(self.pool) + (1 if self._start else 0)

    def observe(self, page: dict) -> None:
        self._last = page
        if not page.get("error"):
            self.visited += 1

    def stop_reason(self) -> Optional[str]:
        return self._stop

    def pop(self) -> Optional[tuple[str, int]]:
        if self._start is not None:
            s, self._start = self._start, None
            self.log.append({"step": 0, "action": "visit", "url": s[0], "reason": "start page", "by": "system"})
            return s
        if self.step >= self.max_steps:
            self._stop = f"agent step budget reached ({self.max_steps})"
            return None
        if not self.pool:
            self._stop = "no more candidate links"
            return None
        self.step += 1
        ranked = sorted(self.pool.items(),
                        key=lambda kv: -heuristic_score(kv[0], kv[1][1], self.watch + [self.goal]))
        cands = ranked[: self.n_candidates]
        decision, by = None, "ai"
        try:
            decision = self.router.agent_step(
                goal=self.goal, watch=", ".join(self.watch) or "(none)",
                step=self.step, max_steps=self.max_steps, visited=self.visited,
                notes="\n".join(f"- {n}" for n in self.notes[-15:]) or "(none)",
                last_url=self._last.get("url", ""),
                last_summary=(self._last.get("analysis") or {}).get("summary", "")[:600]
                or (self._last.get("error") or ""),
                candidates="\n".join(f"{i}. {u} | {t[:100]}" for i, (u, (_, t)) in enumerate(cands)),
            )
        except AIError as e:
            logger.info("agent falling back to heuristic: %s", e)
            by = "heuristic"
        if decision and decision.get("note"):
            self.notes.append(str(decision["note"])[:300])
        if decision and str(decision.get("action", "")).lower() == "stop":
            self._stop = f"agent: {decision.get('reason') or 'goal reached'}"
            self.log.append({"step": self.step, "action": "stop", "reason": decision.get("reason", ""), "by": by})
            return None
        idx = 0
        if decision is not None:
            try:
                idx = int(decision.get("index"))
            except (TypeError, ValueError):
                idx = 0
            if not 0 <= idx < len(cands):
                idx = 0
        url, (depth, _) = cands[idx]
        del self.pool[url]
        self.log.append({"step": self.step, "action": "visit", "url": url, "by": by,
                         "reason": (decision or {}).get("reason", "highest heuristic score")})
        return url, depth
