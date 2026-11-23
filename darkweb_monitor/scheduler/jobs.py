"""APScheduler-based recurring crawl jobs."""
from __future__ import annotations

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config.settings import settings
from ..storage.db import init_db
from ..storage.models import Target
from ..storage.db import session_scope
from ..pipeline import run_crawl

logger = logging.getLogger(__name__)

_scheduler = None


def _run_all_targets():
    init_db()
    with session_scope() as s:
        targets = s.query(Target).filter_by(active=True).all()
        urls = [(t.url, t.keywords) for t in targets]
    for url, kw in urls:
        try:
            run_crawl(url, keywords=kw)
        except Exception as e:
            logger.exception("crawl failed for %s: %s", url, e)


def start_scheduler():
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(_run_all_targets, IntervalTrigger(minutes=settings.SCHEDULE_INTERVAL_MIN))
    _scheduler.start()
    logger.info("Scheduler started: every %d min", settings.SCHEDULE_INTERVAL_MIN)
    return _scheduler


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown()
        _scheduler = None