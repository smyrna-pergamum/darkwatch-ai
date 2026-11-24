"""Tools of the assistant agent (read-only: help, system state, suggestions)."""
from __future__ import annotations

from ..harness.tools import RunContext, ToolDefinition, ToolRegistry
from . import kb


def app_help(args, ctx: RunContext):
    topics = kb.search(args.get("question", ""), k=int(args.get("limit") or 3))
    return {"topics": [{"id": t["id"], "title": t["title"], "text": t["body"]} for t in topics]}


def app_status(args, ctx: RunContext):
    from .. import readiness, tor_manager
    from ..ai import engine
    return {"setup_checklist": [{k: st[k] for k in ("title", "done", "detail", "next")} for st in readiness.checklist()],
            "tor": {**readiness.tor_state(), "built_in": {k: tor_manager.state[k] for k in
                                                         ("status", "progress", "transport", "error")}},
            "ai": {**readiness.ai_state(), "engine_setup": {k: engine.state[k] for k in ("status", "step", "error")}},
            "deferred_crawls": readiness.deferred()}


def suggest_queries(args, ctx: RunContext):
    from .suggest import suggestions
    s = suggestions(use_ai=False)
    return {"queries": [{"label": q["label"], "prompt": q["prompt"], "why": q["why"]} for q in s["queries"]],
            "recommendations": [r["text"] for r in s["recommendations"]]}


def register(reg: ToolRegistry) -> None:
    reg.register(ToolDefinition(
        "app_help", "Search the built-in user guide of DarkWatch AI (how to use every page and feature, "
        "Tor, AI engine, organizations, targets, evidence, troubleshooting).",
        {"properties": {"question": {"type": "string", "minLength": 2, "maxLength": 300},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 5}}, "required": ["question"]},
        app_help))
    reg.register(ToolDefinition(
        "app_status", "Current state of the installation: setup checklist in order (Tor, AI, organisation, "
        "watchlist, targets, first crawl), Tor and AI readiness, deferred crawls.", {"properties": {}}, app_status))
    reg.register(ToolDefinition(
        "suggest_queries", "Data-driven investigation questions and recommendations for this installation.",
        {"properties": {}}, suggest_queries))
