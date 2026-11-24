"""Order of operations.

Start-up runs in a fixed order and work only starts once what it depends on is ready:

  1. database   - tables / migrations, interrupted runs recovered
  2. Tor        - built-in Tor (if chosen) starts; external Tor is checked
  3. AI         - Ollama model checked, built-in llama.cpp started / set up
  4. scheduler  - schedules begin; crawls wait for Tor, they no longer fail

Crawls that come due while Tor is not ready are deferred and started
automatically once Tor connects (``resume_deferred`` runs every minute).
The same order drives the dashboard's setup checklist.
"""
from __future__ import annotations

import logging
import threading

from config.settings import settings

logger = logging.getLogger(__name__)
_deferred: set[int] = set()
_dlock = threading.Lock()
boot: dict = {"phase": "not started", "done": [], "errors": {}}


class NotReady(ValueError):
    """Work refused because a prerequisite (Tor, AI) is not ready yet."""


# ------------------------------------------------------------------ prerequisites
def tor_state(force: bool = False) -> dict:
    from . import tor_manager
    from .crawler.tor_client import tor_status
    if not settings.TOR_REQUIRED:
        return {"ready": True, "reason": "TOR_REQUIRED=false (lab mode)"}
    m = tor_manager.state
    if settings.TOR_MODE == "managed" and m["status"] in ("starting", "downloading", "connecting"):
        return {"ready": False, "reason": f"built-in Tor is connecting ({m['progress']}% {m['summary']})".strip()}
    st = tor_status(force=force)
    if st["is_tor"]:
        return {"ready": True, "reason": f"Tor exit {st.get('exit_ip') or ''}".strip()}
    return {"ready": False, "reason": tor_hint(st)}


def tor_hint(st: dict) -> str:
    err = st.get("error") or "IsTor=false"
    if st.get("reachable"):
        return (f"a Tor proxy answers on {st['proxy']} but is not connected to the Tor network "
                "(still starting, or Tor is blocked on this network) - use Connect under System → Tor; "
                "the built-in Tor falls back to bridges automatically")
    return f"no Tor on {st['proxy']} ({err[:120]}) - use Connect under System → Tor"


def ai_state() -> dict:
    from .ai import engine
    from .ai.router import get_router
    if engine.state["status"] == "running":
        return {"ready": False, "reason": f"built-in AI is being set up ({engine.state['step']}: {engine.state['detail']})"}
    try:
        if get_router().available("page"):
            return {"ready": True, "reason": ""}
    except Exception as e:  # noqa: BLE001
        return {"ready": False, "reason": str(e)[:200]}
    return {"ready": False, "reason": "no local AI model - use \"Set up built-in AI\" (AI & Models); "
                                      "rule-based analysis is used meanwhile"}


def require_tor() -> None:
    """For user-started crawls: refuse with a clear message instead of a failed run."""
    st = tor_state()
    if not st["ready"]:
        st = tor_state(force=True)
    if not st["ready"]:
        raise NotReady("Tor is not connected: " + st["reason"])


# ------------------------------------------------------------------ deferred crawls
def defer_or_run(target_id: int, submit) -> str:
    """Scheduled crawl: run now if Tor is ready, otherwise remember it."""
    if tor_state()["ready"]:
        submit(target_id=target_id, trigger="schedule")
        return "queued"
    with _dlock:
        _deferred.add(target_id)
    logger.info("crawl of target %s deferred: waiting for Tor", target_id)
    return "deferred"


def deferred() -> list[int]:
    with _dlock:
        return sorted(_deferred)


def resume_deferred(submit) -> int:
    with _dlock:
        if not _deferred:
            return 0
    if not tor_state()["ready"]:
        return 0
    with _dlock:
        ids = sorted(_deferred)
        _deferred.clear()
    n = 0
    for tid in ids:
        try:
            submit(target_id=tid, trigger="schedule")
            n += 1
        except Exception as e:  # noqa: BLE001
            logger.warning("deferred crawl of target %s not queued: %s", tid, e)
    if n:
        logger.info("Tor ready: %d deferred crawl(s) started", n)
    return n


# ------------------------------------------------------------------ start-up
def _phase(name: str, fn) -> None:
    boot["phase"] = name
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        logger.warning("start-up phase %s failed: %s", name, e)
        boot["errors"][name] = str(e)[:300]
    boot["done"].append(name)


def startup() -> None:
    """Called once from the API lifespan, in dependency order."""
    from .ai import engine, models
    from .analyst.service import recover as recover_analyst
    from .runner import get_manager
    from .scheduler.jobs import start_scheduler
    from .storage.db import init_db
    from . import tor_manager

    def database():
        init_db()
        n = get_manager().recover()
        if n:
            logger.warning("%d interrupted run(s) marked as failed", n)
        recover_analyst()

    def ai():
        models.autostart()                       # built-in llama.cpp with the active model
        threading.Thread(target=engine.maybe_auto_setup, daemon=True, name="ai-auto-setup").start()

    _phase("database", database)
    _phase("tor", tor_manager.autostart)         # built-in Tor connects in the background
    _phase("ai", ai)
    _phase("scheduler", start_scheduler)         # crawls defer until Tor is ready
    boot["phase"] = "running"


def shutdown() -> None:
    from .ai.llamacpp import managed
    from .runner import get_manager
    from .scheduler.jobs import stop_scheduler
    from . import tor_manager
    stop_scheduler()
    get_manager().shutdown()
    managed.stop()
    tor_manager._kill()


# ------------------------------------------------------------------ checklist
def checklist() -> list[dict]:
    """Ordered setup steps; the first not-done one is what the user should do next."""
    from sqlalchemy import func
    from .storage.db import session_scope
    from .storage.models import CrawlRun, Target, WatchItem
    from .storage.models_intel import Organization, OrgAsset
    tor, ai = tor_state(), ai_state()
    with session_scope() as s:
        orgs = s.query(func.count(Organization.id)).scalar() or 0
        assets = s.query(func.count(OrgAsset.id)).scalar() or 0
        watch = s.query(func.count(WatchItem.id)).filter(WatchItem.active.is_(True)).scalar() or 0
        targets = s.query(func.count(Target.id)).filter(Target.approval == "approved", Target.active.is_(True)).scalar() or 0
        runs_ok = s.query(func.count(CrawlRun.id)).filter(CrawlRun.status == "done").scalar() or 0
    keys = [k for k in ("HIBP_API_KEY", "INTELX_API_KEY", "RANSOMWARE_LIVE_API_KEY") if getattr(settings, k, "")]
    steps = [
        {"id": "tor", "title": "Connect to Tor", "done": tor["ready"], "detail": tor["reason"],
         "action": {"label": "Connect Tor", "call": "tor-connect"}},
        {"id": "ai", "title": "Local AI engine", "done": ai["ready"], "detail": ai["reason"] or "AI is ready",
         "action": {"label": "Set up built-in AI", "call": "ai-setup"}, "optional": True},
        {"id": "org", "title": "Add your organisation and its assets", "done": orgs > 0 and assets > 0,
         "detail": f"{orgs} organisation(s), {assets} asset(s)", "action": {"label": "Organizations", "view": "orgs"}},
        {"id": "watch", "title": "Activate watch terms", "done": watch > 0, "detail": f"{watch} active term(s)",
         "action": {"label": "Watchlist", "view": "watchlist"}},
        {"id": "targets", "title": "Add .onion targets to monitor", "done": targets > 0,
         "detail": f"{targets} approved target(s)", "action": {"label": "Targets", "view": "targets"}},
        {"id": "crawl", "title": "Run the first crawl", "done": runs_ok > 0, "detail": f"{runs_ok} finished run(s)",
         "action": {"label": "Runs", "view": "runs"}, "needs": "tor"},
        {"id": "sources", "title": "Optional: intel source API keys", "done": bool(keys), "optional": True,
         "detail": ", ".join(keys) or "HIBP / IntelX / ransomware.live keys go in .env",
         "action": {"label": "Sources", "view": "sources"}},
    ]
    nxt = next((st["id"] for st in steps if not st["done"] and not st.get("optional")), None)
    for st in steps:
        st["next"] = st["id"] == nxt
        st["blocked"] = bool(st.get("needs") and not next(x for x in steps if x["id"] == st["needs"])["done"])
    return steps
