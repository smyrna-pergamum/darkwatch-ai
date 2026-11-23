"""Hybrid AI router: privacy classes, provider fallback and context budgeting.

Privacy model
-------------
* RAW tasks see dark-web page text or link anchors (page analysis, link
  scoring, agent steps): only *local* providers (same machine / LAN), unless
  ``CLOUD_ALLOW_RAW=true``.
* DERIVED tasks only see locally produced summaries / statistics (run summary,
  triage, task planning): remote providers first, local fallback; redacted
  (``CLOUD_REDACT``) before leaving the box.

Small models
------------
Inputs are measured against each provider's context window. Content that
does not fit is split into chunks (map), the partial answers are merged
(reduce, hierarchically when needed). A "context too long" error shrinks the
budget and retries instead of failing.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import Counter

from config.settings import settings
from . import prompts
from .base import AIError, redact
from .context import ContextBudget, budget_for, chunk_text, estimate_tokens

logger = logging.getLogger(__name__)

RAW_TASKS = {"page", "link_score", "agent_step", "lesson"}
DERIVED_TASKS = {"triage", "run_summary", "planner", "condense", "merge"}
SEVERITIES = ("low", "medium", "high", "critical")
MAX_OVERFLOW_RETRIES = 3


def _sev(v, default="low") -> str:
    v = str(v or "").lower().strip()
    return v if v in SEVERITIES else default


def _is_remote(client) -> bool:
    spec = getattr(client, "spec", None)
    if spec is not None:
        return not spec.is_local
    return getattr(client, "name", "") in ("cloud", "openai", "anthropic") or \
        str(getattr(client, "name", "")).startswith(("env:openai", "env:anthropic"))


def fit_lines(lines: list[str], max_chars: int) -> list[str]:
    out, total = [], 0
    for ln in lines:
        if total + len(ln) + 1 > max_chars:
            break
        out.append(ln)
        total += len(ln) + 1
    return out


class AIRouter:
    def __init__(self, local=None, cloud=None):
        # Explicit clients (tests / embedding); otherwise the provider registry decides.
        self._fixed = local is not None or cloud is not None
        self.local, self.cloud = local, cloud
        self.routing = settings.AI_ROUTING.lower()
        self._stats_lock = threading.Lock()
        self.stats = {"calls": 0, "errors": 0, "chunked_calls": 0, "overflow_retries": 0, "by_provider": {}}

    # ------------------------------------------------------------ providers
    def providers_for(self, task: str) -> list:
        raw = task in RAW_TASKS
        if self._fixed:
            local = [self.local] if self.local is not None else []
            cloud = [self.cloud] if self.cloud is not None else []
            if self.routing == "local":
                order = local
            elif raw:
                order = local + (cloud if settings.CLOUD_ALLOW_RAW else [])
            else:
                order = cloud + local
            return [p for p in order if p.available()]
        from .providers import get_client, ordered_for
        out = []
        for spec in ordered_for(raw):
            c = get_client(spec)
            try:
                if c.available():
                    out.append(c)
            except Exception:  # noqa: BLE001
                continue
        return out

    def available(self, task: str = "page") -> bool:
        return bool(self.providers_for(task))

    def _count(self, name: str, ok: bool) -> None:
        with self._stats_lock:
            self.stats["calls"] += 1
            if not ok:
                self.stats["errors"] += 1
            self.stats["by_provider"][name] = self.stats["by_provider"].get(name, 0) + 1

    def _call(self, client, prompt: str):
        text = redact(prompt) if (_is_remote(client) and settings.CLOUD_REDACT) else prompt
        try:
            res = client.chat_json(text, system=prompts.SYSTEM_ANALYST)
            self._count(client.name, True)
            return res
        except AIError:
            self._count(client.name, False)
            raise

    def _ask(self, task: str, prompt: str):
        """Single prompt with provider fallback (prompt assumed to fit)."""
        providers = self.providers_for(task)
        if not providers:
            raise AIError(f"no AI provider available for task '{task}'")
        last = None
        for p in providers:
            try:
                return self._call(p, prompt)
            except AIError as e:
                last = e
                logger.warning("AI %s failed on %s: %s", p.name, task, e)
        raise AIError(str(last), getattr(last, "code", "AI_ERROR"))

    def _with_budget(self, task: str, fn):
        """Run ``fn(client, budget)`` on each provider; shrink the budget on overflow."""
        providers = self.providers_for(task)
        if not providers:
            raise AIError(f"no AI provider available for task '{task}'")
        last = None
        for p in providers:
            budget = budget_for(p)
            for _ in range(MAX_OVERFLOW_RETRIES):
                try:
                    return fn(p, budget)
                except AIError as e:
                    last = e
                    if getattr(e, "code", "") == "CONTEXT_OVERFLOW":
                        self.stats["overflow_retries"] += 1
                        budget = budget.shrink(0.5)
                        logger.info("context overflow on %s/%s - retrying with window %d", p.name, task, budget.window)
                        continue
                    logger.warning("AI %s failed on %s: %s", p.name, task, e)
                    break
        raise AIError(str(last), getattr(last, "code", "AI_ERROR"))

    # ------------------------------------------------------------ reduce helpers
    def _condense(self, client, items: list[str], budget: ContextBudget, depth: int = 0) -> list[str]:
        """Hierarchically condense notes until they fit one prompt."""
        joined = "\n".join(items)
        if len(joined) <= budget.input_chars or depth >= 3:
            return fit_lines(items, budget.input_chars)
        groups, cur = [], []
        for it in items:
            if cur and len("\n".join(cur + [it])) > budget.input_chars:
                groups.append(cur)
                cur = []
            cur.append(it[: budget.input_chars])
        if cur:
            groups.append(cur)
        points: list[str] = []
        for g in groups:
            res = self._call(client, prompts.PROMPT_CONDENSE.format(notes="\n".join(g)))
            points += [f"- {p}" for p in (res.get("points") if isinstance(res, dict) else None) or [] if p]
            self.stats["chunked_calls"] += 1
        return self._condense(client, points or [joined[: budget.input_chars]], budget, depth + 1)

    # ------------------------------------------------------------ tasks
    def analyze_page(self, url: str, title: str, content: str, watch: list[str] | None = None) -> dict:
        content = (content or "")[: settings.AI_PAGE_MAX_CHARS]
        watch_s = ", ".join(watch or [])[:1500] or "(none)"

        def run(client, budget: ContextBudget) -> dict:
            overhead = estimate_tokens(prompts.PROMPT_PAGE + prompts.SYSTEM_ANALYST + watch_s + url + title) + 50
            b = ContextBudget(budget.window, budget.reserve_output, overhead)
            chunks = chunk_text(content, b.input_chars, max_chunks=settings.AI_MAX_CHUNKS)
            parts = []
            for i, ch in enumerate(chunks, 1):
                res = self._call(client, prompts.PROMPT_PAGE.format(
                    url=url, title=title, watch=watch_s, part=f"{i}/{len(chunks)}", content=ch))
                if not isinstance(res, dict):
                    raise AIError("page analysis: expected object")
                parts.append(res)
            if len(chunks) > 1:
                self.stats["chunked_calls"] += len(chunks)
            return self._merge_page(client, b, url, parts)
        return self._with_budget("page", run)

    def _merge_page(self, client, budget: ContextBudget, url: str, parts: list[dict]) -> dict:
        sevs = [_sev(p.get("severity")) for p in parts]
        severity = max(sevs, key=SEVERITIES.index) if sevs else "low"
        cats = [str(p.get("category") or "unknown")[:32] for p in parts]
        top = [c for p, c in zip(parts, cats, strict=True) if _sev(p.get("severity")) == severity and c not in ("unknown", "other")]
        category = (Counter(top).most_common(1) or Counter(c for c in cats if c not in ("unknown", "other")).most_common(1)
                    or [("unknown", 0)])[0][0]

        def union(key, limit, lim_len=120):
            seen, out = set(), []
            for p in parts:
                for x in p.get(key) or []:
                    s = str(x)[:lim_len]
                    if s.lower() not in seen:
                        seen.add(s.lower())
                        out.append(s)
            return out[:limit]
        iocs, seen = [], set()
        for p in parts:
            for i in p.get("iocs") or []:
                if isinstance(i, dict) and i.get("value") and str(i["value"]).lower() not in seen:
                    seen.add(str(i["value"]).lower())
                    iocs.append(i)
        summaries = [str(p.get("summary") or "").strip() for p in parts if p.get("summary")]
        summary = summaries[0] if len(summaries) == 1 else ""
        if len(summaries) > 1:
            notes = [f"[part {i}] {s}" for i, s in enumerate(summaries, 1)]
            notes = self._condense(client, notes, budget)
            try:
                res = self._call(client, prompts.PROMPT_MERGE.format(url=url, parts="\n".join(notes)))
                summary = str((res or {}).get("summary") or "") if isinstance(res, dict) else ""
            except AIError as e:
                if e.code == "CONTEXT_OVERFLOW":
                    raise
            summary = summary or " ".join(summaries)[:1500]
        rel = []
        for p in parts:
            try:
                rel.append(float(p.get("relevance") or 0))
            except (TypeError, ValueError):
                pass
        return {"summary": summary[:2000], "category": category, "severity": severity,
                "relevance": max(rel) if rel else 0.0, "entities": union("entities", 30),
                "keywords_found": union("keywords_found", 30), "iocs": iocs[:100], "parts": len(parts)}

    def score_links(self, links: list[dict], focus: list[str]) -> dict:
        focus_s = ", ".join(focus)[:800] or "new leaks and threats"

        def run(client, budget: ContextBudget) -> dict:
            per = max(5, budget.input_chars // 140)
            out: dict = {}
            for start in range(0, len(links), per):
                batch = links[start:start + per]
                lines = "\n".join(f"{i}. {lk['url'][:100]}  |  {lk.get('text', '')[:80]}" for i, lk in enumerate(batch))
                res = self._call(client, prompts.PROMPT_LINK_SCORE.format(focus=focus_s, links=lines))
                for item in (res.get("scores") if isinstance(res, dict) else None) or []:
                    try:
                        i = int(item.get("i"))
                        if 0 <= i < len(batch):
                            out[batch[i]["url"]] = max(0.0, min(10.0, float(item.get("score", 0))))
                    except (TypeError, ValueError, AttributeError):
                        continue
            return out
        return self._with_budget("link_score", run)

    def agent_step(self, **kw) -> dict:
        def run(client, budget: ContextBudget) -> dict:
            k = dict(kw)
            room = budget.input_chars - len(prompts.PROMPT_AGENT_STEP)
            # trim the variable parts (oldest notes first, then lowest-ranked candidates)
            notes = str(k.get("notes", "")).splitlines()
            cands = str(k.get("candidates", "")).splitlines()
            k["last_summary"] = str(k.get("last_summary", ""))[: max(200, room // 6)]
            while notes and len("\n".join(notes)) > room // 4:
                notes.pop(0)
            k["notes"] = "\n".join(notes) or "(none)"
            k["candidates"] = "\n".join(fit_lines(cands, max(300, room - len(k["notes"]) - len(k["last_summary"]))))
            res = self._call(client, prompts.PROMPT_AGENT_STEP.format(**k))
            if not isinstance(res, dict):
                raise AIError("agent step: expected object")
            return res
        return self._with_budget("agent_step", run)

    def triage_alert(self, title: str, severity: str, matches: list, summary: str, iocs: list) -> dict:
        def run(client, budget: ContextBudget) -> dict:
            room = budget.input_chars - len(prompts.PROMPT_TRIAGE)
            res = self._call(client, prompts.PROMPT_TRIAGE.format(
                title=title[:300], severity=severity, matches=json.dumps(matches)[: room // 4],
                summary=summary[: room // 2], iocs=", ".join(str(i) for i in iocs[:20])[: room // 4] or "(none)"))
            if not isinstance(res, dict):
                raise AIError("triage: expected object")
            res["severity"] = _sev(res.get("severity"), severity)
            return res
        return self._with_budget("triage", run)

    def summarize_run(self, start_url: str, pages: list, iocs_found: int, alerts_raised: int,
                      alerts: list | None = None, ioc_types: dict | None = None,
                      keywords: list | None = None, mode: str = "standard",
                      changed: int = 0, notes: list | None = None) -> dict:
        sev_counts: dict = {}
        for a in alerts or []:
            sev_counts[a.get("severity", "low")] = sev_counts.get(a.get("severity", "low"), 0) + 1
        ranked = sorted(pages, key=lambda p: (-(SEVERITIES.index(_sev(p.get("severity")))), not p.get("changed")))
        lines = [f"- [{_sev(p.get('severity'))}{'|changed' if p.get('changed') else ''}] "
                 f"{p.get('title') or p.get('url')}: {(p.get('summary') or '')[:300]}" for p in ranked[:60]]

        def run(client, budget: ContextBudget) -> dict:
            b = ContextBudget(budget.window, budget.reserve_output,
                              estimate_tokens(prompts.PROMPT_RUN_SUMMARY) + 300)
            condensed = self._condense(client, lines, b) if lines else []
            res = self._call(client, prompts.PROMPT_RUN_SUMMARY.format(
                url=start_url, mode=mode, pages=len(pages), changed=changed, iocs=iocs_found,
                alerts=alerts_raised, sev_counts=sev_counts or "{}", ioc_types=ioc_types or "{}",
                keywords=", ".join(keywords or [])[:600] or "(none)",
                notes="; ".join(notes or [])[:800] or "(none)",
                page_summaries="\n".join(condensed) or "- (no pages analysed)"))
            if not isinstance(res, dict):
                raise AIError("run summary: expected object")
            return {
                "summary": str(res.get("summary") or ""),
                "risk_level": _sev(res.get("risk_level")),
                "key_findings": [str(x) for x in (res.get("key_findings") or [])][:10],
                "recommendations": [str(x) for x in (res.get("recommendations") or [])][:10],
                "provider": "ai",
            }
        return self._with_budget("run_summary", run)

    def draft_lesson(self, title: str, matches: list, ai_verdict: str, human_label: str, comment: str,
                     context: str) -> dict:
        """Generalise one corrected case into a reusable lesson (stays 'proposed')."""
        def run(client, budget: ContextBudget) -> dict:
            res = self._call(client, prompts.PROMPT_LESSON.format(
                title=title[:300], matches=", ".join(f"{m.get('kind')}:{m.get('value')}" for m in matches)[:400],
                ai_verdict=ai_verdict or "(none)", label=human_label or "(none)", comment=comment[:1200] or "(none)",
                context=context[: max(300, budget.input_chars // 3)]))
            if not isinstance(res, dict) or not res.get("text"):
                raise AIError("lesson draft: expected object with text")
            return {"title": str(res.get("title") or title)[:300], "text": str(res["text"])[:1500],
                    "terms": [str(t)[:80] for t in (res.get("terms") or [])][:8]}
        return self._with_budget("lesson", run)

    def plan_tasks(self, **kw) -> list[dict]:
        def run(client, budget: ContextBudget) -> list[dict]:
            k = dict(kw)
            room = budget.input_chars - len(prompts.PROMPT_PLANNER)
            for key, share in (("run_summary", 4), ("changed", 6), ("alerts", 6), ("discovered", 8), ("watch", 8)):
                k[key] = str(k.get(key, ""))[: max(150, room // share)]
            res = self._call(client, prompts.PROMPT_PLANNER.format(**k))
            tasks = res.get("tasks") if isinstance(res, dict) else None
            return [t for t in (tasks or []) if isinstance(t, dict)]
        return self._with_budget("planner", run)

    def status(self) -> dict:
        raw = self.providers_for("page")
        der = self.providers_for("run_summary")
        local = raw[0] if raw else None
        out = {
            "routing": self.routing,
            "local_backend": settings.LOCAL_AI_BACKEND,
            "local_available": bool(raw),
            "local_model": getattr(local, "model", "") if local else "",
            "cloud_available": any(_is_remote(c) for c in der),
            "cloud_provider": settings.AI_CLOUD_PROVIDER,
            "cloud_allow_raw": settings.CLOUD_ALLOW_RAW,
            "cloud_redact": settings.CLOUD_REDACT,
            "raw_tasks_provider": [c.name for c in raw],
            "derived_tasks_provider": [c.name for c in der],
            "stats": self.stats,
        }
        if local is not None:
            try:
                out["local_context_window"] = budget_for(local).window
            except Exception:  # noqa: BLE001
                pass
        return out


_router: AIRouter | None = None


def get_router() -> AIRouter:
    global _router
    if _router is None:
        _router = AIRouter()
    return _router


def set_router(r: AIRouter | None) -> None:
    """Used by tests to inject fakes."""
    global _router
    _router = r
