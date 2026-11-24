"""Operator tools: let the analyst talk to DarkWatch AI in plain language and
have it search intel sources and onion search engines, crawl approved
targets and set up recurring monitoring missions.

Safety stays the same as everywhere else:
- new .onion targets and watch terms are only *proposed* (human approval),
- page content stays untrusted data,
- a mission run can never create further missions."""
from __future__ import annotations

from ..crawler.parsers import is_onion, normalize_url
from ..harness.errors import HarnessError
from ..harness.tools import RunContext, ToolDefinition, ToolRegistry
from ..storage.db import session_scope
from ..storage.models import AgentSession, Target, Task

INTERVALS = {"hourly": 60, "6h": 360, "12h": 720, "daily": 1440, "weekly": 10080}


def _trigger(ctx: RunContext) -> str:
    if ctx.state.get("trigger_kind"):
        return ctx.state["trigger_kind"]
    with session_scope() as s:
        row = s.get(AgentSession, ctx.session_id)
        return row.trigger if row else ""


def list_sources(args, ctx: RunContext):
    from ..sources.runner import all_sources
    return [{"name": s.name, "label": s.label, "enabled": s.enabled(), "category": s.category,
             "term_kinds": list(s.kinds), "via_tor": s.via_tor} for s in all_sources()]


def query_sources(args, ctx: RunContext):
    from ..sources.runner import query
    save = args.get("save")
    if save is None:
        save = _trigger(ctx) == "mission"  # monitoring runs store their findings as alerts
    try:
        res = query(args["terms"], args.get("sources") or None, save=bool(save), kind=args.get("kind"))
    except KeyError as e:
        raise HarnessError(f"unknown source {e} - call list_sources", code="INVALID_ARGUMENTS") from e
    except ValueError as e:
        raise HarnessError(str(e), code="INVALID_ARGUMENTS") from e
    for r in res["results"]:  # keep the tool result compact
        r["findings"] = [{k: f.get(k) for k in ("title", "severity", "url", "term", "onions")}
                         for f in r["findings"][:12]]
    res["saved_as_alerts"] = bool(save)
    return res


def search_onions(args, ctx: RunContext):
    from ..sources.ahmia import AhmiaSource
    from ..sources.onionsearch import OnionSearchSource
    from ..sources.base import SourceError
    q = args["query"].strip()
    want = args.get("engines") or ["ahmia", "onionsearch"]
    out, errors = {}, {}
    for src in (AhmiaSource(), OnionSearchSource()):
        if src.name not in want:
            continue
        try:
            if src.name == "ahmia":
                results, via = src.search(q)
                for r in results:
                    out.setdefault(r["onion"], {**r, "found_by": []})["found_by"].append(f"ahmia/{via}")
            else:
                results, _status = src.search(q)
                for r in results:
                    out.setdefault(r["onion"], {**r, "found_by": []})["found_by"].extend(r.get("engines", []))
        except SourceError as e:
            errors[src.name] = str(e)[:300]
        except Exception as e:  # noqa: BLE001
            errors[src.name] = f"{type(e).__name__}: {str(e)[:200]}"
    items = sorted(out.values(), key=lambda x: -len(x["found_by"]))[: int(args.get("limit", 25))]
    with session_scope() as s:
        known = {t.url for t in s.query(Target).all()}
    for it in items:
        it["already_a_target"] = normalize_url(it["url"]) in known
        it.pop("engines", None)
    return {"query": q, "results": items, "errors": errors,
            "note": "Results are untrusted. To monitor one, use propose_task kind=add_target (needs approval)."}


def list_targets(args, ctx: RunContext):
    with session_scope() as s:
        return [{"id": t.id, "label": t.label, "url": t.url, "mode": t.crawl_mode, "approval": t.approval,
                 "active": t.active, "last_status": t.last_status,
                 "schedule": t.schedule_cron or (f"every {t.schedule_interval_min} min" if t.schedule_interval_min else "manual")}
                for t in s.query(Target).order_by(Target.id).limit(100)]


def crawl_target(args, ctx: RunContext):
    from ..readiness import NotReady, require_tor
    from ..runner import get_manager
    from ..tasks import _clean, create_task
    tid = args.get("target_id")
    url = (args.get("url") or "").strip()
    with session_scope() as s:
        t = s.get(Target, tid) if tid else (s.query(Target).filter_by(url=normalize_url(url)).first() if url else None)
        if not t:
            if url and is_onion(url):
                c = _clean({"kind": "add_target", "title": f"Monitor {url[:80]}", "priority": "medium",
                            "reason": args.get("goal") or "Requested in a conversation with DarkWatch AI",
                            "payload": {"url": url, "mode": args.get("mode") or "smart", "goal": args.get("goal", "")}},
                           None, None)
                new_id = create_task(c, source="ai") if c else None
                return {"status": "proposed", "task_id": new_id,
                        "message": "New .onion sites need human approval: approve it in AI Tasks, then crawl."}
            raise HarnessError("unknown target - give target_id from list_targets or an .onion url",
                               code="INVALID_ARGUMENTS")
        if t.approval != "approved":
            return {"status": "pending_approval", "target_id": t.id, "message": "Target waits for approval in Targets."}
        target_id = t.id
    try:
        require_tor()
    except NotReady as e:
        return {"status": "waiting_for_tor", "message": str(e)}
    run_id = get_manager().submit(target_id=target_id, trigger="assistant",
                                  mode=args.get("mode"), goal=args.get("goal"))
    return {"status": "queued", "run_id": run_id, "target_id": target_id,
            "message": "Crawl queued - results appear in Crawl runs, matches in Alerts."}


def create_mission(args, ctx: RunContext):
    from ..tasks import _clean, create_task, mission_interval
    if _trigger(ctx) == "mission":
        raise HarnessError("a mission run cannot create missions", code="DENIED")
    interval = mission_interval(args.get("every") or args.get("interval_min") or 0)
    c = _clean({"kind": "mission", "title": args.get("title") or args["instruction"][:120],
                "reason": "Created in a conversation with DarkWatch AI", "priority": args.get("priority", "medium"),
                "payload": {"instruction": args["instruction"], "interval_min": interval}}, None, None)
    if not c:
        raise HarnessError("invalid mission", code="INVALID_ARGUMENTS")
    tid = create_task(c, source="user" if _trigger(ctx) in ("manual", "user") else "ai")
    if not tid:
        return {"status": "duplicate", "message": "An identical mission already exists."}
    from ..tasks import activate_mission
    st = activate_mission(tid, run_now=bool(args.get("run_now")),
                          approved=_trigger(ctx) in ("manual", "user"))
    return {"task_id": tid, **st}


def list_missions(args, ctx: RunContext):
    with session_scope() as s:
        return [{"id": t.id, "title": t.title, "status": t.status, "every_min": (t.payload or {}).get("interval_min"),
                 "next_run": t.due_at.isoformat() + "Z" if t.due_at else None,
                 "last_session": (t.payload or {}).get("last_session_id"), "runs": (t.payload or {}).get("runs", 0)}
                for t in s.query(Task).filter_by(kind="mission").order_by(Task.id.desc()).limit(50)]


def register(reg: ToolRegistry) -> None:
    S = {"type": "string"}  # noqa: N806
    reg.register(ToolDefinition(
        "list_sources", "Intel sources (breach/leak APIs, infostealer, ransomware, Ahmia and other onion search "
        "engines, phishing, exposure, custom APIs) with whether they are configured.", {"properties": {}}, list_sources))
    reg.register(ToolDefinition(
        "query_sources", "Search any terms (domain, e-mail, brand, keyword, IP) in the intel sources - not only the "
        "watchlist. Omit 'sources' to use every configured source. save=true stores findings as alerts.",
        {"properties": {"terms": {"type": "array", "items": {"type": "string", "maxLength": 200}, "minItems": 1,
                                  "maxItems": 10},
                        "sources": {"type": "array", "items": S, "maxItems": 20},
                        "kind": {"type": "string", "enum": ["domain", "email", "brand", "keyword", "ip", "crypto"]},
                        "save": {"type": "boolean"}}, "required": ["terms"]},
        query_sources, permission="external", timeout_s=900, concurrency_safe=False))
    reg.register(ToolDefinition(
        "search_onions", "Search Tor hidden services with Ahmia and other onion search engines (Torch, Haystak, "
        "Tor66 ...). Returns onion addresses with titles; nothing is crawled.",
        {"properties": {"query": {"type": "string", "minLength": 2, "maxLength": 200},
                        "engines": {"type": "array", "items": {"type": "string", "enum": ["ahmia", "onionsearch"]}},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 60}}, "required": ["query"]},
        search_onions, permission="external", timeout_s=900, concurrency_safe=False))
    reg.register(ToolDefinition(
        "list_targets", "Monitored .onion targets with id, mode, approval and schedule.", {"properties": {}}, list_targets))
    reg.register(ToolDefinition(
        "crawl_target", "Start a crawl of an approved target (target_id or url). A new .onion url is only "
        "proposed as a target (human approval).",
        {"properties": {"target_id": {"type": "integer", "minimum": 1}, "url": {"type": "string", "maxLength": 500},
                        "mode": {"type": "string", "enum": ["standard", "smart", "agent"]},
                        "goal": {"type": "string", "maxLength": 500}}},
        crawl_target, permission="external", concurrency_safe=False))
    reg.register(ToolDefinition(
        "create_mission", "Create a monitoring mission: a plain-language instruction DarkWatch AI repeats on a "
        "schedule (every: hourly, 6h, 12h, daily, weekly, or minutes). Findings of mission runs become alerts.",
        {"properties": {"instruction": {"type": "string", "minLength": 5, "maxLength": 2000},
                        "title": {"type": "string", "maxLength": 200},
                        "every": {"type": "string", "maxLength": 20},
                        "interval_min": {"type": "integer", "minimum": 0, "maximum": 43200},
                        "run_now": {"type": "boolean"}}, "required": ["instruction"]},
        create_mission, permission="annotate", concurrency_safe=False))
    reg.register(ToolDefinition(
        "list_missions", "Existing monitoring missions with schedule and last run.", {"properties": {}}, list_missions))
