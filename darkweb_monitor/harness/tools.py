"""Tool registry and the guarded execution pipeline.

    validate args
      -> tools/pre-execute  (waterfall: policy -> allow | deny | ask)
      -> ask: record an approval, return APPROVAL_PENDING (body skipped)
      -> tools/execute      (waterfall around the body; timeout)
      -> render content
      -> tools/post-execute (waterfall: retention / redaction / rewrite)
      -> normalised ToolResult (errors keep their stable code)
"""
from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutTimeout
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .errors import (
    ApprovalPending, HarnessError, ToolDenied, ToolTimeout, UnknownTool, to_harness_error,
)
from .hooks import HookBus
import fnmatch

from .schema import repair, validate

logger = logging.getLogger(__name__)

# permission levels, least to most impactful
PERMISSIONS = ("read", "external", "annotate", "write")
_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tool")


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict
    execute: Callable[[dict, "RunContext"], Any]
    permission: str = "read"
    render: Optional[Callable[[dict, Any], str]] = None
    timeout_s: float = 30.0
    concurrency_safe: bool = True
    terminal: bool = False  # e.g. submit_report: ends the investigation

    def schema(self) -> dict:
        """Model-facing fields only (allow-list - host metadata never leaks)."""
        return {"name": self.name, "description": self.description,
                "parameters": {"type": "object", "additionalProperties": False, **self.parameters}}


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class ToolResult:
    id: str
    name: str
    content: str
    is_error: bool = False
    value: Any = None
    error: Optional[dict] = None
    truncated: bool = False
    approval_id: Optional[int] = None

    def event(self) -> dict:
        return {"id": self.id, "name": self.name, "content": self.content, "is_error": self.is_error,
                "value": self.value, "error": self.error, "truncated": self.truncated,
                "approval_id": self.approval_id}


@dataclass
class Decision:
    action: str  # allow | deny | ask
    reason: str = ""


@dataclass
class RunContext:
    session_id: int
    agent: str
    call: ToolCall
    tool: ToolDefinition
    state: dict = field(default_factory=dict)  # per-session scratch shared by tools


class ToolRegistry:
    def __init__(self, hooks: HookBus | None = None):
        self.hooks = hooks or HookBus()
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> Callable[[], None]:
        if tool.permission not in PERMISSIONS:
            raise ValueError(f"unknown permission {tool.permission}")
        self._tools[tool.name] = tool
        return lambda: self._tools.pop(tool.name, None)

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def resolve(self, name: str) -> Optional[ToolDefinition]:
        """Exact name, else a case/separator-insensitive match (small models
        often write ``GetAlert`` or ``get-alert``)."""
        if name in self._tools:
            return self._tools[name]
        norm = re.sub(r"[^a-z0-9]", "", (name or "").lower())
        for n, t in self._tools.items():
            if re.sub(r"[^a-z0-9]", "", n) == norm:
                return t
        return None

    def names(self) -> list[str]:
        return sorted(self._tools)

    def schemas(self, allow: list[str] | None = None) -> list[dict]:
        return [t.schema() for n, t in sorted(self._tools.items()) if allow is None or n in allow]

    # ------------------------------------------------------------ pipeline
    def execute(self, call: ToolCall, session_id: int, agent: str, state: dict,
                approve: Callable[[RunContext, str], int] | None = None) -> ToolResult:
        tool = self.resolve(call.name)
        try:
            if tool is None:
                raise UnknownTool(f"no tool named '{call.name}'. Available: {', '.join(self.names())}")
            params = tool.schema()["parameters"]
            args = validate(repair(call.args, params), params)
            ctx = RunContext(session_id, agent, ToolCall(call.id, call.name, args), tool, state)
            decision: Decision = self.hooks.waterfall("tools/pre-execute", Decision("allow"), ctx, lambda d: d)
            if decision.action == "deny":
                raise ToolDenied(decision.reason or "denied by policy")
            if decision.action == "ask":
                if approve is None:
                    raise ToolDenied("approval required but no approver is available")
                aid = approve(ctx, decision.reason)
                raise ApprovalPending(
                    f"Queued for human approval (#{aid}): {decision.reason or tool.permission + ' action'}. "
                    "It has NOT been executed. Do not assume it happened; continue your analysis.", aid)

            def body(_ctx):
                fut = _POOL.submit(tool.execute, args, _ctx)
                try:
                    return fut.result(timeout=tool.timeout_s)
                except FutTimeout:
                    raise ToolTimeout(f"{tool.name} exceeded {tool.timeout_s}s") from None
            value = self.hooks.waterfall("tools/execute", ctx, ctx, body)
            content = tool.render(args, value) if tool.render else _default_render(value)
            result = ToolResult(call.id, call.name, content, value=value)
            return self.hooks.waterfall("tools/post-execute", result, ctx, lambda r: r)
        except Exception as exc:  # noqa: BLE001 - normalise every failure
            err = to_harness_error(exc)
            if err.code == "INTERNAL":
                logger.exception("tool %s crashed", call.name)
            return ToolResult(call.id, call.name, f"[{err.code}] {err}", is_error=True,
                              error=err.as_dict(), approval_id=getattr(err, "approval_id", None))


def _default_render(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str, indent=1)


# ------------------------------------------------------------------ policies
def permission_policy(auto: set[str], ask: set[str]) -> Callable:
    """tools/pre-execute handler: auto-allow, ask or deny by permission level."""
    def handler(decision: Decision, ctx: RunContext, nxt):
        perm = ctx.tool.permission
        if perm in auto:
            return nxt(decision)
        if perm in ask:
            return nxt(Decision("ask", f"'{ctx.tool.name}' is a {perm} action"))
        return nxt(Decision("deny", f"'{ctx.tool.name}' ({perm}) is not allowed for this agent"))
    return handler


def retention_policy(max_chars: int) -> Callable:
    """tools/post-execute handler: bound model-facing content."""
    def handler(result: ToolResult, ctx: RunContext, nxt):
        if len(result.content) > max_chars:
            result.content = result.content[:max_chars] + f"\n…[truncated {len(result.content) - max_chars} chars]"
            result.truncated = True
        return nxt(result)
    return handler


def rules_policy(rules: list[tuple[str, str]]) -> Callable:
    """opencode-style ruleset: [(tool glob, allow|ask|deny)], last match wins.
    Runs before the permission-level policy and short-circuits it when a rule matches."""
    def handler(decision: Decision, ctx: RunContext, nxt):
        effect = None
        for pattern, eff in rules:
            if fnmatch.fnmatch(ctx.tool.name, pattern):
                effect = eff
        if effect is None:
            return nxt(decision)
        if effect == "allow":
            return decision
        if effect == "deny":
            return Decision("deny", f"'{ctx.tool.name}' is denied for this agent")
        return Decision("ask", f"'{ctx.tool.name}' requires approval")
    return handler


def parse_rules(text: str) -> list[tuple[str, str]]:
    out = []
    for part in (text or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            if v.strip() in ("allow", "ask", "deny"):
                out.append((k.strip(), v.strip()))
    return out


def doom_loop_guard(repeats: int = 3) -> Callable:
    """Deny the Nth identical consecutive call (same tool + same arguments)."""
    def handler(decision: Decision, ctx: RunContext, nxt):
        sig = ctx.tool.name + json.dumps(ctx.call.args, sort_keys=True, default=str)
        hist = ctx.state.setdefault("call_history", [])
        hist.append(sig)
        if len(hist) >= repeats and len(set(hist[-repeats:])) == 1:
            return Decision("deny", f"You called {ctx.tool.name} with identical arguments {repeats} times in a row. "
                                    "Use what you already have, change approach, or submit your report.")
        return nxt(decision)
    return handler


def call_budget_guard(max_calls: int) -> Callable:
    """tools/pre-execute handler: stop runaway tool use within a session."""
    def handler(decision: Decision, ctx: RunContext, nxt):
        n = ctx.state["tool_calls"] = ctx.state.get("tool_calls", 0) + 1
        if n > max_calls:
            return Decision("deny", f"tool-call budget of {max_calls} exhausted - submit your report now")
        return nxt(decision)
    return handler


__all__ = ["ToolDefinition", "ToolRegistry", "ToolCall", "ToolResult", "Decision", "RunContext",
           "permission_policy", "retention_policy", "call_budget_guard", "rules_policy", "parse_rules",
           "doom_loop_guard", "HarnessError"]
