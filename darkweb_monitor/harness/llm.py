"""Model adapter seam with native tool calling.

Internal message format (OpenAI-like):
    {"role": "user" | "assistant" | "tool", "content": str,
     "tool_calls": [{"id", "name", "args"}], "tool_call_id", "name", "is_error"}

Adapters are built from the provider registry (``ai.providers``):
  OllamaChat        native /api/chat tools
  OpenAICompatChat  any OpenAI-compatible server: LM Studio, llama-server,
                    vLLM, LocalAI, Jan, OpenRouter, Groq, OpenAI, ...
  LlamaCppChat      the built-in llama.cpp backend (server / managed / embedded)
  AnthropicChat     Messages API tools
  JsonProtocol      tools described in the prompt, for models without native tools
  Scripted          deterministic (tests / evals)
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from config.settings import settings
from ..ai.base import redact
from ..ai.context import is_context_overflow
from .errors import LlmError


@dataclass
class AssistantTurn:
    content: str = ""
    tool_calls: list[dict] = field(default_factory=list)  # [{"id","name","args"}]
    usage: dict = field(default_factory=dict)


def _cid() -> str:
    return "call_" + uuid.uuid4().hex[:12]


def _parse_args(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {"_raw": v}
    except (TypeError, ValueError):
        return {"_raw": str(raw)[:500]}


def llm_error(prefix: str, detail) -> LlmError:
    msg = f"{prefix}: {detail}"
    if is_context_overflow(msg):
        return LlmError(msg, code="CONTEXT_OVERFLOW", retryable=False)
    if "does not support tools" in msg.lower() or ("tool" in msg.lower() and "not support" in msg.lower()):
        return LlmError(msg, code="NO_NATIVE_TOOLS", retryable=False)
    return LlmError(msg)


class Adapter:
    name = "base"
    model = ""
    raw_capable = False   # may receive raw (untrusted dark-web) content
    redact = False
    window = 4096

    def available(self) -> bool:
        return True

    def context_window(self) -> int:
        return self.window

    def complete(self, system: str, messages: list[dict], tools: list[dict]) -> AssistantTurn:
        raise NotImplementedError

    def json_fallback(self) -> Optional["Adapter"]:
        return None

    def _prep(self, messages: list[dict]) -> list[dict]:
        if not self.redact:
            return messages
        return [{**m, "content": redact(m.get("content") or "")} for m in messages]


def _openai_messages(system: str, messages: list[dict]) -> list[dict]:
    msgs = [{"role": "system", "content": system}]
    for m in messages:
        if m["role"] == "assistant":
            am = {"role": "assistant", "content": m.get("content") or ""}
            if m.get("tool_calls"):
                am["tool_calls"] = [{"id": c["id"], "type": "function", "function": {
                    "name": c["name"], "arguments": json.dumps(c["args"])}} for c in m["tool_calls"]]
            msgs.append(am)
        elif m["role"] == "tool":
            msgs.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        else:
            msgs.append({"role": "user", "content": m["content"]})
    return msgs


def _turn_from_openai(msg: dict, usage: dict | None = None) -> AssistantTurn:
    calls = [{"id": c.get("id") or _cid(), "name": c.get("function", {}).get("name", ""),
              "args": _parse_args(c.get("function", {}).get("arguments"))} for c in msg.get("tool_calls") or []]
    content = msg.get("content") or ""
    if not calls and content:
        calls = _calls_in_text(content)  # some small models print tool calls as text
    return AssistantTurn(content, calls, usage or {})


_TEXT_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


def _calls_in_text(content: str) -> list[dict]:
    out = []
    for m in _TEXT_CALL.finditer(content):
        try:
            obj = json.loads(m.group(1))
            out.append({"id": _cid(), "name": str(obj.get("name", "")),
                        "args": _parse_args(obj.get("arguments") or obj.get("args"))})
        except ValueError:
            continue
    return out


# ------------------------------------------------------------------ Ollama
class OllamaChat(Adapter):
    raw_capable = True

    def __init__(self, base_url: str | None = None, model: str | None = None, name: str = "env:ollama"):
        self.name = name
        self.model = model or settings.ANALYST_MODEL or settings.OLLAMA_MODEL
        self.base = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")

    def available(self) -> bool:
        try:
            return httpx.get(f"{self.base}/api/tags", timeout=4).status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def context_window(self) -> int:
        from ..ai.context import detect_context_window
        n = detect_context_window("ollama", self.base, self.model)
        return min(n, settings.OLLAMA_NUM_CTX) if n else settings.OLLAMA_NUM_CTX

    def json_fallback(self):
        from ..ai.local import OllamaClient
        c = OllamaClient(base_url=self.base, model=self.model)
        return JsonProtocol(lambda sys, prompt: c.generate(prompt, system=sys, json_mode=True),
                            self.name, self.model, True, window=self.context_window())

    def complete(self, system, messages, tools):
        msgs = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "assistant":
                msgs.append({"role": "assistant", "content": m.get("content") or "",
                             "tool_calls": [{"function": {"name": c["name"], "arguments": c["args"]}}
                                            for c in m.get("tool_calls", [])]})
            elif m["role"] == "tool":
                msgs.append({"role": "tool", "content": m["content"], "tool_name": m.get("name")})
            else:
                msgs.append({"role": "user", "content": m["content"]})
        payload = {"model": self.model, "messages": msgs, "stream": False,
                   "options": {"temperature": 0.1, "num_ctx": settings.OLLAMA_NUM_CTX},
                   "tools": [{"type": "function", "function": t} for t in tools]}
        try:
            r = httpx.post(f"{self.base}/api/chat", json=payload, timeout=settings.OLLAMA_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            raise LlmError(f"ollama: {e}") from e
        if r.status_code >= 400:
            raise llm_error(f"ollama HTTP {r.status_code}", r.text[:300])
        d = r.json()
        if d.get("prompt_eval_count") and d["prompt_eval_count"] >= settings.OLLAMA_NUM_CTX - 8:
            raise LlmError("ollama: prompt filled the context window", code="CONTEXT_OVERFLOW", retryable=False)
        msg = d.get("message") or {}
        calls = [{"id": _cid(), "name": c.get("function", {}).get("name", ""),
                  "args": _parse_args(c.get("function", {}).get("arguments"))} for c in msg.get("tool_calls") or []]
        if not calls and msg.get("content"):
            calls = _calls_in_text(msg["content"])
        return AssistantTurn(msg.get("content") or "", calls,
                             {"in": d.get("prompt_eval_count"), "out": d.get("eval_count")})


# ------------------------------------------------------ OpenAI-compatible
class OpenAICompatChat(Adapter):
    def __init__(self, spec):
        from ..ai.providers import OpenAICompatClient
        self.spec = spec
        self.client = OpenAICompatClient(spec)
        self.name, self.model = spec.key, spec.model
        self.raw_capable = spec.is_local or settings.CLOUD_ALLOW_RAW
        self.redact = (not spec.is_local) and settings.CLOUD_REDACT

    def available(self) -> bool:
        return self.client.available()

    def context_window(self) -> int:
        return self.client.context_window()

    def json_fallback(self):
        return JsonProtocol(lambda sys, prompt: self.client.generate(prompt, system=sys, json_mode=True),
                            self.name, self.model, self.raw_capable, self.redact, window=self.context_window())

    def complete(self, system, messages, tools):
        if not self.spec.supports_tools:
            return self.json_fallback().complete(system, messages, tools)
        try:
            msg = self.client.chat(_openai_messages(system, self._prep(messages)),
                                   tools=[{"type": "function", "function": t} for t in tools])
        except Exception as e:  # noqa: BLE001
            raise llm_error(self.name, e) from e
        return _turn_from_openai(msg)


# ------------------------------------------------------------------ llama.cpp
class LlamaCppChat(Adapter):
    """Built-in llama.cpp backend: native tools via llama-server --jinja,
    JSON protocol in embedded mode or when tools are rejected."""
    name = "env:llamacpp"
    raw_capable = True

    def __init__(self):
        from ..ai.llamacpp import LlamaCppClient
        self.client = LlamaCppClient()
        self.model = self.client.model

    def available(self) -> bool:
        return self.client.available()

    def context_window(self) -> int:
        return self.client.context_window()

    def json_fallback(self):
        return JsonProtocol(lambda sys, prompt: self.client.generate(prompt, system=sys, json_mode=True),
                            self.name, self.model, True, window=self.context_window())

    def complete(self, system, messages, tools):
        if settings.LLAMACPP_MODE == "embedded":
            return self.json_fallback().complete(system, messages, tools)
        try:
            msg = self.client.chat(_openai_messages(system, messages),
                                   tools=[{"type": "function", "function": t} for t in tools])
        except Exception as e:  # noqa: BLE001
            raise llm_error("llama.cpp", e) from e
        return _turn_from_openai(msg)


# ---------------------------------------------------------------- Anthropic
class AnthropicChat(Adapter):
    def __init__(self, spec=None):
        self.name = spec.key if spec else "env:anthropic"
        self.model = (spec.model if spec else "") or settings.ANTHROPIC_MODEL
        self.key = (spec.api_key if spec else "") or settings.ANTHROPIC_API_KEY
        self.raw_capable = settings.CLOUD_ALLOW_RAW
        self.redact = settings.CLOUD_REDACT
        self._c = None

    def available(self) -> bool:
        return bool(self.key)

    def context_window(self) -> int:
        return max(settings.AI_REMOTE_CONTEXT, 32000)

    def complete(self, system, messages, tools):
        try:
            if self._c is None:
                import anthropic
                self._c = anthropic.Anthropic(api_key=self.key, timeout=120)
            out: list[dict] = []

            def push(role, blocks):
                if out and out[-1]["role"] == role:
                    out[-1]["content"].extend(blocks)
                else:
                    out.append({"role": role, "content": list(blocks)})
            for m in self._prep(messages):
                if m["role"] == "assistant":
                    blocks = ([{"type": "text", "text": m["content"]}] if m.get("content") else []) + \
                             [{"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]}
                              for c in m.get("tool_calls", [])]
                    push("assistant", blocks or [{"type": "text", "text": "…"}])
                elif m["role"] == "tool":
                    push("user", [{"type": "tool_result", "tool_use_id": m["tool_call_id"],
                                   "content": m["content"], "is_error": bool(m.get("is_error"))}])
                else:
                    push("user", [{"type": "text", "text": m["content"]}])
            resp = self._c.messages.create(
                model=self.model, max_tokens=2500, system=system, messages=out, temperature=0.1,
                tools=[{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
                       for t in tools])
            text = "".join(getattr(b, "text", "") for b in resp.content if b.type == "text")
            calls = [{"id": b.id, "name": b.name, "args": dict(b.input or {})}
                     for b in resp.content if b.type == "tool_use"]
            u = getattr(resp, "usage", None)
            return AssistantTurn(text, calls, {"in": getattr(u, "input_tokens", None),
                                               "out": getattr(u, "output_tokens", None)})
        except LlmError:
            raise
        except Exception as e:  # noqa: BLE001
            raise llm_error("anthropic", e) from e


# ------------------------------------------------------------ JSON protocol
JSON_PROTOCOL = """
You can call tools. Reply with ONE JSON object and nothing else, either
  {"thought": "<short reasoning>", "tool_calls": [{"name": "<tool>", "args": {...}}]}
or, when you have nothing more to do,
  {"final": "<short message to the human>"}
Available tools (JSON schema of args):
"""


class JsonProtocol(Adapter):
    """Tool calling for models without native support, over a text generate()."""

    def __init__(self, inner_generate: Callable[[str, str], str], name: str, model: str, raw_capable: bool,
                 redact_cloud: bool = False, window: int = 4096):
        self.gen, self.name, self.model = inner_generate, name + "+json", model
        self.raw_capable, self.redact, self.window = raw_capable, redact_cloud, window

    def complete(self, system, messages, tools):
        sys_full = system + "\n" + JSON_PROTOCOL + "\n".join(
            f"- {t['name']}: {t['description'][:200]} args={json.dumps(t['parameters'].get('properties', {}))}"
            for t in tools)
        lines = []
        for m in self._prep(messages):
            if m["role"] == "assistant":
                lines.append("ASSISTANT: " + json.dumps({"thought": m.get("content", ""),
                                                         "tool_calls": [{"name": c["name"], "args": c["args"]}
                                                                        for c in m.get("tool_calls", [])]}))
            elif m["role"] == "tool":
                lines.append(f"TOOL RESULT {m.get('name')}: {m['content']}")
            else:
                lines.append("USER: " + m["content"])
        try:
            raw = self.gen(sys_full, "\n\n".join(lines) + "\n\nASSISTANT (JSON only):")
        except Exception as e:  # noqa: BLE001
            raise llm_error(self.name, e) from e
        m = re.search(r"\{.*\}", raw or "", re.DOTALL)
        try:
            obj = json.loads(m.group(0)) if m else {}
        except ValueError:
            obj = {}
        if not obj:
            return AssistantTurn(content=(raw or "").strip()[:2000])
        calls = [{"id": _cid(), "name": str(c.get("name", "")),
                  "args": c.get("args") if isinstance(c.get("args"), dict) else {}}
                 for c in obj.get("tool_calls") or [] if isinstance(c, dict)]
        return AssistantTurn(content=str(obj.get("final") or obj.get("thought") or ""), tool_calls=calls)


# ----------------------------------------------------------------- scripted
class Scripted(Adapter):
    """Deterministic adapter for tests and evals: ``script(messages, tools) -> AssistantTurn``."""
    name = "scripted"
    raw_capable = True

    def __init__(self, script: Callable[[list[dict], list[dict]], AssistantTurn], window: int = 32000):
        self.script, self.window = script, window
        self.requests: list[dict] = []

    def complete(self, system, messages, tools):
        self.requests.append({"system": system, "messages": messages, "tools": [t["name"] for t in tools]})
        res = self.script(messages, tools)
        if isinstance(res, Exception):
            raise res
        return res


# ----------------------------------------------------------------- selection
def adapter_for(spec) -> Optional[Adapter]:
    if spec.kind == "ollama":
        return OllamaChat(spec.base_url, settings.ANALYST_MODEL or spec.model, spec.key)
    if spec.kind == "llamacpp":
        return LlamaCppChat()
    if spec.kind == "anthropic":
        return AnthropicChat(spec)
    return OpenAICompatChat(spec)


def select_adapter(preference: str | None = None) -> Optional[Adapter]:
    """First available provider the privacy policy allows for an agent that
    reads raw dark-web content (local providers; remote only with CLOUD_ALLOW_RAW).
    ``preference``: "auto", "rules", a provider key ("db:3", "env:ollama") or a kind."""
    from ..ai.providers import all_providers, ordered_for
    pref = (preference or settings.ANALYST_PROVIDER or "auto").strip()
    if pref == "rules":
        return None
    specs = ordered_for(raw=True)
    if pref != "auto":
        specs = [s for s in all_providers() if s.key == pref or s.kind == pref or s.preset == pref] or specs
        specs = [s for s in specs if s.enabled and (s.is_local or settings.CLOUD_ALLOW_RAW)]
    for spec in specs:
        a = adapter_for(spec)
        try:
            if a and a.available() and a.raw_capable:
                return a
        except Exception:  # noqa: BLE001
            continue
    return None
