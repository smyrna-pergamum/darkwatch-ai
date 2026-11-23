"""Background run manager: queues crawl runs on a small worker pool so the
API never blocks, supports cancellation and recovers after restarts."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from config.settings import settings
from .crawler.parsers import normalize_url
from .storage.db import audit, session_scope
from .storage.models import CrawlRun, Target, utcnow

logger = logging.getLogger(__name__)


class RunManager:
    def __init__(self, workers: int | None = None):
        self.workers = max(1, workers or settings.CRAWL_CONCURRENCY)
        self._pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="crawl")
        self._flags: dict[int, threading.Event] = {}
        self._lock = threading.Lock()

    def recover(self) -> int:
        """Mark runs left running/queued by a previous process as failed."""
        with session_scope() as s:
            stale = s.query(CrawlRun).filter(CrawlRun.status.in_(("queued", "running"))).all()
            for r in stale:
                r.status, r.error, r.finished_at = "failed", "interrupted (process restarted)", utcnow()
            return len(stale)

    def submit(self, *, target_id: int | None = None, url: str | None = None, keywords: str = "",
               depth: int | None = None, mode: str | None = None, goal: str | None = None,
               max_pages: int | None = None, trigger: str = "manual") -> int:
        with session_scope() as s:
            if target_id:
                t = s.get(Target, target_id)
                if not t:
                    raise ValueError("target not found")
            else:
                if not url:
                    raise ValueError("url or target_id required")
                nurl = normalize_url(url)
                t = s.query(Target).filter_by(url=nurl).first()
                if not t:
                    t = Target(url=nurl, keywords=keywords, crawl_mode=mode or "standard",
                               agent_goal=goal or "")
                    s.add(t)
                    s.flush()
            if t.approval != "approved":
                raise ValueError("target is pending approval")
            active = s.query(CrawlRun).filter(CrawlRun.target_id == t.id,
                                              CrawlRun.status.in_(("queued", "running"))).first()
            if active:
                return active.id  # never run the same target twice in parallel
            run = CrawlRun(target_id=t.id, start_url=t.url, mode=mode or t.crawl_mode or "standard",
                           trigger=trigger, status="queued")
            s.add(run)
            s.flush()
            run_id, tid = run.id, t.id
        flag = threading.Event()
        with self._lock:
            self._flags[run_id] = flag
        self._pool.submit(self._execute, run_id, tid, keywords, depth, mode, goal, max_pages, trigger, flag)
        audit("run.queue", f"run {run_id} target={tid} trigger={trigger}")
        return run_id

    def _execute(self, run_id, tid, keywords, depth, mode, goal, max_pages, trigger, flag):
        from .pipeline import run_crawl
        try:
            if flag.is_set():
                return
            run_crawl(target_id=tid, run_id=run_id, keywords=keywords, depth=depth, mode=mode,
                      goal=goal, max_pages=max_pages, trigger=trigger, should_stop=flag.is_set)
        except Exception as e:  # noqa: BLE001
            logger.exception("run %s crashed", run_id)
            with session_scope() as s:
                r = s.get(CrawlRun, run_id)
                if r and r.status in ("queued", "running"):
                    r.status, r.error, r.finished_at = "failed", str(e)[:2000], utcnow()
        finally:
            with self._lock:
                self._flags.pop(run_id, None)

    def cancel(self, run_id: int) -> bool:
        with self._lock:
            flag = self._flags.get(run_id)
        if flag:
            flag.set()
        with session_scope() as s:
            r = s.get(CrawlRun, run_id)
            if r and r.status == "queued":
                r.status, r.finished_at, r.error = "cancelled", utcnow(), "cancelled before start"
                return True
            return bool(flag)

    def active_ids(self) -> list[int]:
        with self._lock:
            return list(self._flags)

    def shutdown(self) -> None:
        for f in list(self._flags.values()):
            f.set()
        self._pool.shutdown(wait=False, cancel_futures=True)


_manager: RunManager | None = None


def get_manager() -> RunManager:
    global _manager
    if _manager is None:
        _manager = RunManager()
    return _manager
