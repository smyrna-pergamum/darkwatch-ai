"""APScheduler jobs: per-target crawl schedules (interval or cron), due
follow-up tasks, external sources, threat feeds and data retention."""
from __future__ import annotations

import logging
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from config.settings import settings
from ..storage.db import audit, session_scope
from ..storage.models import Page, Target, utcnow

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None


def _crawl_target(target_id: int) -> None:
    from ..readiness import defer_or_run
    from ..runner import get_manager
    try:
        defer_or_run(target_id, get_manager().submit)  # waits for Tor instead of failing
    except Exception as e:  # noqa: BLE001
        logger.warning("scheduled crawl for target %s not queued: %s", target_id, e)


def _resume_deferred() -> None:
    from ..readiness import resume_deferred
    from ..runner import get_manager
    resume_deferred(get_manager().submit)


def _due_tasks() -> None:
    from ..runner import get_manager
    from ..tasks import run_due_tasks
    run_due_tasks(lambda **kw: get_manager().submit(**kw))


def _sources() -> None:
    from ..sources.runner import run_all_sources
    run_all_sources()


def _analyst() -> None:
    from ..analyst.service import auto_investigate
    auto_investigate()


def _learning() -> None:
    from ..learning.rules import propose
    propose()


def _org_risk() -> None:
    from ..intel.risk import refresh_all
    from ..storage.db import session_scope
    with session_scope() as s:
        logger.info("org risk refreshed for %d organisation(s)", refresh_all(s))


def _feeds() -> None:
    from ..sources.feeds import refresh_feeds
    logger.info("feeds refreshed: %s", refresh_feeds())


def apply_retention() -> int:
    """GDPR / data minimisation: purge stored page text after RETENTION_DAYS."""
    if not settings.RETENTION_DAYS:
        return 0
    cutoff = utcnow() - timedelta(days=settings.RETENTION_DAYS)
    with session_scope() as s:
        rows = s.query(Page).filter(Page.crawled_at < cutoff, Page.content_purged.is_(False)).all()
        for p in rows:
            p.content, p.content_purged = "", True
        n = len(rows)
    if n:
        audit("retention.purge", f"purged content of {n} page(s) older than {settings.RETENTION_DAYS}d")
    return n


def target_trigger(t: Target):
    if t.schedule_cron:
        try:
            return CronTrigger.from_crontab(t.schedule_cron)
        except ValueError:
            logger.warning("invalid cron for target %s: %r", t.id, t.schedule_cron)
            return None
    if t.schedule_interval_min and t.schedule_interval_min > 0:
        return IntervalTrigger(minutes=max(15, t.schedule_interval_min))
    return None


def sync_jobs() -> int:
    """(Re)create one job per scheduled, active, approved target."""
    if _scheduler is None:
        return 0
    for job in _scheduler.get_jobs():
        if job.id.startswith("target-"):
            job.remove()
    n = 0
    with session_scope() as s:
        for t in s.query(Target).filter_by(active=True, approval="approved").all():
            trig = target_trigger(t)
            if trig is None:
                continue
            _scheduler.add_job(_crawl_target, trig, args=[t.id], id=f"target-{t.id}",
                               name=f"crawl {t.label or t.url}", max_instances=1,
                               coalesce=True, misfire_grace_time=3600, replace_existing=True)
            n += 1
    return n


def next_runs() -> dict[int, str]:
    if _scheduler is None:
        return {}
    out = {}
    for job in _scheduler.get_jobs():
        if job.id.startswith("target-") and job.next_run_time:
            out[int(job.id.split("-", 1)[1])] = job.next_run_time.isoformat()
    return out


def jobs_overview() -> list[dict]:
    if _scheduler is None:
        return []
    return [{"id": j.id, "name": j.name, "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
             "trigger": str(j.trigger)} for j in _scheduler.get_jobs()]


def start_scheduler() -> BackgroundScheduler | None:
    global _scheduler
    if _scheduler is not None or not settings.SCHEDULER_ENABLED:
        return _scheduler
    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(_resume_deferred, IntervalTrigger(minutes=1), id="resume-deferred",
                       name="start crawls deferred until Tor was ready", replace_existing=True)
    _scheduler.add_job(_due_tasks, IntervalTrigger(minutes=1), id="due-tasks", name="follow-up tasks",
                       max_instances=1, coalesce=True)
    _scheduler.add_job(_analyst, IntervalTrigger(minutes=2), id="analyst-auto", name="AI analyst auto-investigation",
                       max_instances=1, coalesce=True)
    _scheduler.add_job(_learning, IntervalTrigger(hours=24), id="learning", name="propose suppression rules",
                       next_run_time=utcnow() + timedelta(minutes=10))
    _scheduler.add_job(_org_risk, IntervalTrigger(hours=6), id="org-risk", name="organisation risk scores",
                       max_instances=1, coalesce=True, next_run_time=utcnow() + timedelta(minutes=3))
    _scheduler.add_job(apply_retention, IntervalTrigger(hours=24), id="retention", name="data retention",
                       next_run_time=utcnow() + timedelta(minutes=5))
    _scheduler.add_job(_sources, IntervalTrigger(minutes=max(60, settings.SOURCES_INTERVAL_MIN)),
                       id="sources", name="external sources", max_instances=1, coalesce=True,
                       next_run_time=utcnow() + timedelta(minutes=2))
    if settings.FEEDS_ENABLED:
        _scheduler.add_job(_feeds, IntervalTrigger(hours=max(1, settings.FEEDS_INTERVAL_HOURS)), id="feeds",
                           name="threat feeds", max_instances=1, coalesce=True,
                           next_run_time=utcnow() + timedelta(minutes=1))
    _scheduler.start()
    n = sync_jobs()
    logger.info("scheduler started (%d scheduled target(s))", n)
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def scheduler_running() -> bool:
    return _scheduler is not None and _scheduler.running
