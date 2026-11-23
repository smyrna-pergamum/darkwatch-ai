"""CLI entrypoint."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings
from .storage.db import init_db
from .pipeline import run_crawl
from .ai.router import AIRouter


def main():
    parser = argparse.ArgumentParser(description="DarkWeb Monitor CLI")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init", help="Initialize database")
    sub.add_parser("status", help="Show AI/Tor status")

    c = sub.add_parser("crawl", help="Crawl a URL")
    c.add_argument("url")
    c.add_argument("--keywords", default="")
    c.add_argument("--depth", type=int, default=None)

    s = sub.add_parser("serve", help="Run API server")
    s.add_argument("--host", default=settings.API_HOST)
    s.add_argument("--port", type=int, default=settings.API_PORT)

    args = parser.parse_args()

    if args.cmd == "init":
        init_db()
        print("DB initialized at", settings.DATABASE_URL)
    elif args.cmd == "status":
        print(AIRouter().status())
    elif args.cmd == "crawl":
        init_db()
        res = run_crawl(args.url, keywords=args.keywords, depth=args.depth)
        print(f"run {res['run_id']}: {res['pages_crawled']} pages, "
              f"{res['iocs_found']} iocs, {res['alerts_raised']} alerts")
        ai = res.get("ai_summary") or {}
        if ai:
            print(f"\nAI summary (risk: {ai.get('risk_level', 'low')}):\n{ai.get('summary', '')}")
            for key in ("key_findings", "recommendations"):
                vals = ai.get(key) or []
                if vals:
                    print(f"\n{key}:")
                    for v in vals:
                        print(" -", v)
    elif args.cmd == "serve":
        init_db()
        import uvicorn
        from darkweb_monitor.api.main import app
        uvicorn.run(app, host=args.host, port=args.port, reload=False)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()