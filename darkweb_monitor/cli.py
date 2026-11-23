"""Command line interface."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
import time
from pathlib import Path

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings  # noqa: E402
from .storage.db import init_db, session_scope  # noqa: E402


def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(prog="darkweb-monitor", description="DarkWeb Monitor CLI")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init", help="create / upgrade the database")
    st = sub.add_parser("status", help="Tor, AI and source status")
    st.add_argument("--no-tor-check", action="store_true")

    c = sub.add_parser("crawl", help="crawl a URL or target now (foreground)")
    c.add_argument("url", nargs="?")
    c.add_argument("--target", type=int)
    c.add_argument("--keywords", default="")
    c.add_argument("--depth", type=int)
    c.add_argument("--max-pages", type=int)
    c.add_argument("--mode", choices=["standard", "smart", "agent"])
    c.add_argument("--goal", help="goal for agent mode")

    s = sub.add_parser("serve", help="run API, dashboard and scheduler")
    s.add_argument("--host", default=settings.API_HOST)
    s.add_argument("--port", type=int, default=settings.API_PORT)

    sub.add_parser("worker", help="run only the scheduler (no web server)")

    t = sub.add_parser("target", help="manage targets")
    tsub = t.add_subparsers(dest="action")
    tsub.add_parser("list")
    ta = tsub.add_parser("add")
    ta.add_argument("url")
    ta.add_argument("--label", default="")
    ta.add_argument("--mode", default="standard", choices=["standard", "smart", "agent"])
    ta.add_argument("--goal", default="")
    ta.add_argument("--every", type=int, help="schedule interval in minutes")
    ta.add_argument("--cron", default="", help="cron expression, e.g. '0 */6 * * *'")

    w = sub.add_parser("watch", help="manage the watchlist")
    wsub = w.add_subparsers(dest="action")
    wsub.add_parser("list")
    wa = wsub.add_parser("add")
    wa.add_argument("kind", choices=["keyword", "brand", "domain", "email", "ip", "crypto", "regex"])
    wa.add_argument("value")
    wa.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])

    so = sub.add_parser("sources", help="run external intelligence sources")
    so.add_argument("name", nargs="?", help="hibp | intelx | ransomware | ahmia (default: all enabled)")
    sub.add_parser("feeds", help="refresh threat feeds (CISA KEV, Feodo)")
    sub.add_parser("retention", help="purge page content older than RETENTION_DAYS")
    sub.add_parser("newnym", help="request a new Tor circuit")
    an = sub.add_parser("analyst", help="run the AI analyst on an alert (foreground)")
    an.add_argument("alert_id", type=int)
    an.add_argument("--question", default=None)
    an.add_argument("--provider", default=None, help="auto | rules | db:ID | env:ollama | env:llamacpp ...")
    ev = sub.add_parser("analyst-eval", help="evaluate the analyst agent on built-in scenarios")
    ev.add_argument("--provider", default="auto")
    ev.add_argument("--only", nargs="*")
    ev.add_argument("--json", action="store_true")
    ai = sub.add_parser("ai", help="list AI providers and routing")
    ai.add_argument("--check", action="store_true")
    mdl = sub.add_parser("models", help="manage local GGUF models")
    msub = mdl.add_subparsers(dest="action")
    msub.add_parser("list")
    md = msub.add_parser("download")
    md.add_argument("url_or_repo")
    md.add_argument("file", nargs="?")
    mr = msub.add_parser("register")
    mr.add_argument("path")
    ma = msub.add_parser("activate")
    ma.add_argument("id", type=int)
    ex = sub.add_parser("export", help="export indicators")
    ex.add_argument("--format", default="stix", choices=["csv", "json", "stix", "misp"])
    ex.add_argument("--out", default="-")

    a = p.parse_args(argv)

    if a.cmd == "init":
        init_db()
        print("database ready:", settings.DATABASE_URL)
    elif a.cmd == "status":
        from .ai.router import get_router
        from .crawler.tor_client import tor_status
        from .sources.runner import source_status
        init_db()
        _print({"tor": None if a.no_tor_check else tor_status(force=True), "ai": get_router().status(),
                "sources": source_status()})
    elif a.cmd == "crawl":
        from .pipeline import run_crawl
        init_db()
        if not a.url and not a.target:
            p.error("crawl needs a URL or --target")
        res = run_crawl(a.url, keywords=a.keywords, depth=a.depth, target_id=a.target, mode=a.mode,
                        goal=a.goal, max_pages=a.max_pages, trigger="cli")
        print(f"\nrun {res['run_id']} [{res['status']}] pages={res['pages_crawled']} "
              f"changed={res['pages_changed']} iocs={res['iocs_found']} alerts={res['alerts_raised']} "
              f"tasks={len(res['tasks_created'])}")
        if res["error"]:
            print("error:", res["error"])
        ai = res.get("ai_summary") or {}
        print(f"\nsummary (risk {ai.get('risk_level', 'low')}, by {ai.get('provider')}):\n{ai.get('summary', '')}")
        for key in ("key_findings", "recommendations"):
            for v in ai.get(key) or []:
                print(f"  [{key[:4]}] {v}")
        return 0 if res["status"] == "done" else 1
    elif a.cmd == "serve":
        if not _is_loopback(a.host) and not settings.API_KEY:
            print("refusing to listen on a non-loopback address without API_KEY set", file=sys.stderr)
            return 2
        init_db()
        import uvicorn
        from darkweb_monitor.api.main import app
        uvicorn.run(app, host=a.host, port=a.port, reload=False)
    elif a.cmd == "worker":
        from .runner import get_manager
        from .scheduler.jobs import start_scheduler
        init_db()
        get_manager().recover()
        start_scheduler()
        print("scheduler running - Ctrl+C to stop")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    elif a.cmd == "target":
        from .crawler.parsers import normalize_url
        from .storage.models import Target
        init_db()
        with session_scope() as s:
            if a.action == "add":
                url = a.url if a.url.startswith("http") else "http://" + a.url
                t = Target(url=normalize_url(url), label=a.label, crawl_mode=a.mode, agent_goal=a.goal,
                           schedule_interval_min=a.every, schedule_cron=a.cron)
                s.add(t)
                s.flush()
                print("added target", t.id)
            else:
                for t in s.query(Target).order_by(Target.id):
                    sched = f"every {t.schedule_interval_min}m" if t.schedule_interval_min else (t.schedule_cron or "manual")
                    print(f"{t.id:>4} {'on ' if t.active else 'off'} {t.crawl_mode:<8} {sched:<14} {t.last_status:<7} {t.url}")
    elif a.cmd == "watch":
        from .storage.models import WatchItem
        from .watchlist import validate
        init_db()
        with session_scope() as s:
            if a.action == "add":
                err = validate(a.kind, a.value)
                if err:
                    p.error(err)
                s.add(WatchItem(kind=a.kind, value=a.value, severity=a.severity))
                print("added")
            else:
                for wi in s.query(WatchItem).order_by(WatchItem.kind):
                    print(f"{wi.id:>4} {wi.kind:<8} {wi.severity:<8} {wi.value}")
    elif a.cmd == "sources":
        from .sources.runner import run_all_sources, run_source
        init_db()
        _print(run_source(a.name) if a.name else run_all_sources())
    elif a.cmd == "feeds":
        from .sources.feeds import refresh_feeds
        init_db()
        _print(refresh_feeds())
    elif a.cmd == "retention":
        from .scheduler.jobs import apply_retention
        init_db()
        print("purged", apply_retention(), "page(s)")
    elif a.cmd == "newnym":
        from .crawler.tor_client import new_identity
        print(new_identity())
    elif a.cmd == "analyst":
        from .analyst import service
        from .analyst.agent import RulesAdapter
        from .harness.llm import select_adapter
        from .harness.session import SessionLog
        init_db()
        if a.provider:
            service.set_adapter(RulesAdapter() if a.provider == "rules" else (select_adapter(a.provider) or RulesAdapter()))
        sid = service.start(a.alert_id, a.question, trigger="cli")
        service._pool.submit(lambda: None).result()
        for e in SessionLog(sid).events():
            p = e.payload
            if e.type == "assistant/message":
                if p.get("content"):
                    print(f"\n🤖 {p['content']}")
                for c in p.get("tool_calls") or []:
                    print(f"   → {c['name']}({json.dumps(c.get('args'), ensure_ascii=False)[:160]})")
            elif e.type == "tool/result" and p.get("is_error"):
                print(f"   ✗ {p.get('content', '')[:160]}")
            elif e.type == "context/compacted":
                print("   [context compacted]")
            elif e.type == "report/submitted":
                r = p["report"]
                print(f"\n=== REPORT: {r['verdict']} / {r['severity']} (confidence {r['confidence']:.0%}) ===\n{r['summary']}")
                for x in r.get("recommended_actions") or []:
                    print(f"  - {x}")
    elif a.cmd == "analyst-eval":
        from .analyst.evals import format_table, run
        init_db()
        res = run(a.provider, a.only)
        print(json.dumps(res, indent=2) if a.json else format_table(res))
        return 0 if res.get("score", 0) >= 0.75 else 1
    elif a.cmd == "ai":
        from .ai.providers import all_providers, get_client, ordered_for
        init_db()
        for p in all_providers(fresh=True):
            st = ""
            if a.check:
                try:
                    st = "up" if get_client(p).available() else "down"
                except Exception as e:  # noqa: BLE001
                    st = f"error {e}"
            print(f"{p.key:<14} {p.trust:<7} {'on ' if p.enabled else 'off'} prio={p.priority:<4} {p.base_url:<40} {p.model:<30} {st}")
        print("raw content  ->", " -> ".join(p.key for p in ordered_for(True)) or "(none: rules only)")
        print("derived data ->", " -> ".join(p.key for p in ordered_for(False)) or "(none)")
    elif a.cmd == "models":
        from .ai import models as mm
        init_db()
        if a.action == "download":
            url = a.url_or_repo
            if not url.startswith("http"):
                if not a.file:
                    p.error("give a URL, or REPO FILE (e.g. Qwen/Qwen2.5-3B-Instruct-GGUF qwen2.5-3b-instruct-q4_k_m.gguf)")
                url = f"{settings.HF_ENDPOINT}/{url}/resolve/main/{a.file}?download=true"
            m = mm.start_download(url, filename=a.file or "")
            print("downloading", m["path"])
            while True:
                cur = next(x for x in mm.list_models() if x["id"] == m["id"])
                print(f"\r{cur['status']} {cur['progress'] * 100:5.1f}%", end="", flush=True)
                if cur["status"] != "downloading":
                    print("\n", cur["error"] or "done")
                    break
                time.sleep(2)
        elif a.action == "register":
            _print(mm.register_path(a.path))
        elif a.action == "activate":
            _print(mm.activate(a.id))
        else:
            for m in mm.list_models():
                print(f"{m['id']:>3} {'*' if m['active'] else ' '} {m['status']:<11} {m['size_bytes'] / 1e9:6.2f} GB "
                      f"{m['meta'].get('quantization', ''):<8} {m['name']}  ({m['path']})")
    elif a.cmd == "export":
        from . import exports
        from .storage.models import Indicator
        init_db()
        with session_scope() as s:
            rows = s.query(Indicator).all()
            body = {"csv": exports.indicators_csv, "json": exports.indicators_json,
                    "stix": lambda r: json.dumps(exports.indicators_stix(r), indent=2),
                    "misp": lambda r: json.dumps(exports.indicators_misp(r), indent=2)}[a.format](rows)
        if a.out == "-":
            print(body)
        else:
            Path(a.out).write_text(body, encoding="utf-8")
            print("written", a.out)
    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
