"""The agent loop.

    turn/start
      [user/message]
      repeat (step budget):
        step/start
        derive model history from the log (compaction applied deterministically)
        agent/pre-step (waterfall over the message list)
        model request (retry on retryable errors; failed attempts -> assistant/attempt)
        assistant/message
        tool/call* -> pipeline -> tool/result*        (safe calls run in parallel)
        step/end
        no tool calls -> agent/turn-stopping (may inject a message and continue)
    turn/end {reason}
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..ai.context import tokens_to_chars
from .compaction import compact, needs_compaction, reserve_tokens
from .errors import LlmError
from .llm import Adapter
from .session import SessionLog, derive_messages
from .tools import RunContext, ToolCall, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)


@dataclass
class TurnContext:
    log: SessionLog
    agent: str
    step: int = 0
    last_content: str = ""
    state: dict = field(default_factory=dict)


@dataclass
class TurnOutcome:
    reason: str
    steps: int
    final_text: str = ""
    error: str = ""


class AgentLoop:
    def __init__(self, agent: str, registry: ToolRegistry, adapter: Adapter, system_prompt: Callable[[], str],
                 allow_tools: list[str] | None = None, max_steps: int = 12, max_context_chars: int = 60000,
                 approver: Optional[Callable[[RunContext, str], int]] = None,
                 fallback_adapter: Optional[Callable[[], Adapter]] = None, retries: int = 1):
        self.agent, self.registry, self.adapter = agent, registry, adapter
        self.hooks = registry.hooks
        self.system_prompt, self.allow = system_prompt, allow_tools
        self.max_steps, self.max_context_chars = max_steps, max_context_chars
        self.approver, self.fallback_adapter, self.retries = approver, fallback_adapter, retries

    def window(self) -> int:
        try:
            return int(self.adapter.context_window())
        except Exception:  # noqa: BLE001
            return 4096

    def _messages(self, log: SessionLog, tools: list[dict]) -> list[dict]:
        """Derive history; compact it with the model when it would not fit."""
        w = self.window()
        max_chars = min(self.max_context_chars, tokens_to_chars(w - reserve_tokens(w)))
        msgs = derive_messages(log.events(), max_chars=max_chars)
        if needs_compaction(self.system_prompt(), tools, msgs, w):
            if compact(log, self.adapter, w, "auto"):
                msgs = derive_messages(log.events(), max_chars=max_chars)
        return msgs

    def _request(self, log: SessionLog, messages: list[dict], tools: list[dict]):
        last: Exception | None = None
        overflow_retries = 0
        attempt = 0
        while attempt <= self.retries + overflow_retries:
            attempt += 1
            try:
                return self.adapter.complete(self.system_prompt(), messages, tools)
            except LlmError as e:
                last = e
                log.append("assistant/attempt", {"error": e.as_dict(), "attempt": attempt,
                                                 "provider": self.adapter.name})
                if e.code == "NO_NATIVE_TOOLS":
                    fb = self.adapter.json_fallback() if hasattr(self.adapter, "json_fallback") else None
                    fb = fb or (self.fallback_adapter() if self.fallback_adapter else None)
                    if fb:
                        self.adapter = fb
                        continue
                    break
                if e.code == "CONTEXT_OVERFLOW" and overflow_retries < 2:
                    # overflow recovery: compact aggressively, re-derive, retry
                    overflow_retries += 1
                    w = max(1024, self.window() // (2 * overflow_retries))
                    compact(log, self.adapter, w, "overflow")
                    messages = derive_messages(log.events(), max_chars=tokens_to_chars(w - reserve_tokens(w)))
                    continue
                if not e.retryable:
                    break
        raise last  # type: ignore[misc]

    def _run_calls(self, log: SessionLog, calls: list[dict], state: dict) -> list[ToolResult]:
        tcs = [ToolCall(c["id"], c["name"], c.get("args") or {}) for c in calls]
        for tc in tcs:
            log.append("tool/call", {"id": tc.id, "name": tc.name, "args": tc.args})
        parallel = len(tcs) > 1 and all((self.registry.get(t.name) or _Unsafe).concurrency_safe for t in tcs)

        def run(tc: ToolCall) -> ToolResult:
            return self.registry.execute(tc, log.session_id, self.agent, state, self.approver)
        if parallel:
            with ThreadPoolExecutor(max_workers=min(4, len(tcs))) as ex:
                results = list(ex.map(run, tcs))
        else:
            results = [run(tc) for tc in tcs]
        for r in results:  # results are logged in call order for stable replay
            log.append("tool/result", r.event())
        return results

    def run_turn(self, log: SessionLog, user_text: str | None = None, trigger: str = "user",
                 should_stop: Callable[[], bool] = lambda: False, state: dict | None = None) -> TurnOutcome:
        state = state if state is not None else {}
        state.setdefault("agent", self.agent)
        ctx = TurnContext(log, self.agent, state=state)
        turn_no = log.row()["turns"] + 1
        log.update(turns=turn_no, status="running", provider=self.adapter.name, model=self.adapter.model or "")
        log.append("turn/start", {"turn": turn_no, "trigger": trigger, "provider": self.adapter.name,
                                  "model": self.adapter.model})
        if user_text:
            log.append("user/message", {"content": user_text})
        tools = self.registry.schemas(self.allow)
        outcome = TurnOutcome("max_steps", 0)
        try:
            for step in range(1, self.max_steps + 1):
                if should_stop():
                    outcome = TurnOutcome("cancelled", step - 1)
                    break
                ctx.step = step
                log.append("step/start", {"step": step})
                messages = self._messages(log, tools)
                messages = self.hooks.waterfall("agent/pre-step", messages, ctx, lambda m: m)
                turn = self._request(log, messages, tools)
                log.append("assistant/message", {"content": turn.content, "tool_calls": turn.tool_calls,
                                                 "provider": self.adapter.name, "model": self.adapter.model,
                                                 "usage": turn.usage})
                ctx.last_content = turn.content
                row = log.row()
                log.update(steps=row["steps"] + 1, tool_calls=row["tool_calls"] + len(turn.tool_calls))
                if turn.tool_calls:
                    results = self._run_calls(log, turn.tool_calls, state)
                    log.append("step/end", {"step": step, "tool_calls": len(results)})
                    if any(not r.is_error and (self.registry.get(r.name) or _Unsafe).terminal for r in results):
                        outcome = TurnOutcome("completed", step, turn.content)
                        break
                    continue
                log.append("step/end", {"step": step, "tool_calls": 0})
                verdict = self.hooks.serial("agent/turn-stopping", ctx)
                if isinstance(verdict, dict) and verdict.get("continue"):
                    log.append("user/message", {"content": verdict["continue"], "injected": True})
                    continue
                outcome = TurnOutcome("completed", step, turn.content)
                break
            else:
                outcome = TurnOutcome("max_steps", self.max_steps, ctx.last_content)
        except LlmError as e:
            outcome = TurnOutcome("error", ctx.step, error=f"{e.code}: {e}")
        except Exception as e:  # noqa: BLE001
            logger.exception("agent turn crashed")
            outcome = TurnOutcome("error", ctx.step, error=f"{type(e).__name__}: {e}")
        log.append("turn/end", {"turn": turn_no, "reason": outcome.reason, "steps": outcome.steps,
                                "error": outcome.error})
        return outcome


class _Unsafe:
    concurrency_safe = False
    terminal = False
