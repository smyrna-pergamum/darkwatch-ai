"""AI provider registry.

Providers come from two places:
  * environment (.env): Ollama, llama.cpp, OpenAI, Anthropic - "env" providers
  * the database: any number of user-added endpoints (LM Studio, vLLM,
    OpenRouter, Groq, a remote Ollama, ...), managed in the dashboard.

Every provider has a *trust* level:
  local  - runs on this machine / LAN: may receive raw dark-web text
  remote - third-party service: only receives derived, redacted data
           (raw only when CLOUD_ALLOW_RAW=true)
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from config.settings import settings
from .base import AIError, ai_error, parse_json

PRESETS: dict[str, dict] = {
    "lmstudio":  {"label": "LM Studio", "kind": "openai_compat", "base_url": "http://127.0.0.1:1234/v1", "key": False},
    "ollama":    {"label": "Ollama (native API)", "kind": "ollama", "base_url": "http://127.0.0.1:11434", "key": False},
    "ollama_v1": {"label": "Ollama (OpenAI API)", "kind": "openai_compat", "base_url": "http://127.0.0.1:11434/v1", "key": False},
    "llamacpp":  {"label": "llama.cpp server", "kind": "openai_compat", "base_url": "http://127.0.0.1:8080/v1", "key": False},
    "vllm":      {"label": "vLLM", "kind": "openai_compat", "base_url": "http://127.0.0.1:8000/v1", "key": False},
    "localai":   {"label": "LocalAI", "kind": "openai_compat", "base_url": "http://127.0.0.1:8080/v1", "key": False},
    "jan":       {"label": "Jan", "kind": "openai_compat", "base_url": "http://127.0.0.1:1337/v1", "key": False},
    "openai":    {"label": "OpenAI", "kind": "openai_compat", "base_url": "https://api.openai.com/v1", "key": True},
    "anthropic": {"label": "Anthropic", "kind": "anthropic", "base_url": "https://api.anthropic.com", "key": True},
    "openrouter": {"label": "OpenRouter", "kind": "openai_compat", "base_url": "https://openrouter.ai/api/v1", "key": True},
    "groq":      {"label": "Groq", "kind": "openai_compat", "base_url": "https://api.groq.com/openai/v1", "key": True},
    "together":  {"label": "Together AI", "kind": "openai_compat", "base_url": "https://api.together.xyz/v1", "key": True},
    "mistral":   {"label": "Mistral", "kind": "openai_compat", "base_url": "https://api.mistral.ai/v1", "key": True},
    "deepseek":  {"label": "DeepSeek", "kind": "openai_compat", "base_url": "https://api.deepseek.com/v1", "key": True},
    "custom":    {"label": "Custom OpenAI-compatible", "kind": "openai_compat", "base_url": "", "key": False},
}


def guess_trust(base_url: str) -> str:
    host = (urlparse(base_url).hostname or "").lower()
    if host in ("localhost", "host.docker.internal") or host.endswith((".local", ".lan", ".internal")):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
        return "local" if (ip.is_loopback or ip.is_private or ip.is_link_local) else "remote"
    except ValueError:
        return "remote"


@dataclass
class ProviderSpec:
    key: str                  # "env:ollama" | "db:3"
    name: str
    kind: str                 # openai_compat | ollama | llamacpp | anthropic
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    trust: str = "local"
    enabled: bool = True
    priority: int = 100
    supports_tools: bool = True
    context_window: int = 0  # 0 = auto-detect / default
    source: str = "env"
    preset: str = "custom"
    extra: dict = field(default_factory=dict)

    @property
    def is_local(self) -> bool:
        return self.trust == "local"

    def public(self) -> dict:
        k = self.api_key
        return {"key": self.key, "name": self.name, "kind": self.kind, "base_url": self.base_url,
                "model": self.model, "trust": self.trust, "enabled": self.enabled, "priority": self.priority,
                "supports_tools": self.supports_tools, "source": self.source, "preset": self.preset,
                "context_window": self.context_window,
                "api_key_set": bool(k), "api_key_hint": (k[:3] + "…" + k[-3:]) if len(k) > 8 else ("•••" if k else "")}


# ---------------------------------------------------------------- clients
class OpenAICompatClient:
    """Text client over any OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, spec: ProviderSpec):
        self.spec = spec
        self.name = spec.key
        self.model = spec.model
        self._avail = (0.0, False)
        self._json_mode = True

    def context_window(self) -> int:
        if self.spec.context_window:
            return self.spec.context_window
        from .context import detect_context_window
        n = detect_context_window("openai_compat", self.spec.base_url, self.spec.model, self.spec.api_key)
        return n or (settings.AI_DEFAULT_CONTEXT if self.spec.is_local else settings.AI_REMOTE_CONTEXT)

    def _url(self, path: str) -> str:
        return self.spec.base_url.rstrip("/") + path

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.spec.api_key:
            h["Authorization"] = f"Bearer {self.spec.api_key}"
        if "openrouter.ai" in self.spec.base_url:
            h["X-Title"] = "darkweb-monitor"
        return h

    def list_models(self, timeout: float = 8) -> list[str]:
        r = httpx.get(self._url("/models"), headers=self._headers(), timeout=timeout)
        r.raise_for_status()
        data = r.json()
        items = data.get("data", data) if isinstance(data, dict) else data
        return sorted({(m.get("id") or m.get("name")) for m in items if isinstance(m, dict)} - {None})

    def available(self) -> bool:
        if not self.spec.enabled:
            return False
        ts, val = self._avail
        if time.time() - ts < 20:
            return val
        try:
            r = httpx.get(self._url("/models"), headers=self._headers(), timeout=4)
            val = r.status_code < 500 and r.status_code not in (401, 403, 404)
        except Exception:  # noqa: BLE001
            val = False
        self._avail = (time.time(), val)
        return val

    def chat(self, messages: list[dict], json_mode: bool = False, tools: list | None = None,
             timeout: float | None = None) -> dict:
        body = {"model": self.spec.model or "default", "messages": messages, "temperature": 0.1, "stream": False}
        if json_mode and self._json_mode:
            body["response_format"] = {"type": "json_object"}
        if tools:
            body["tools"] = tools
        try:
            r = httpx.post(self._url("/chat/completions"), json=body, headers=self._headers(),
                           timeout=timeout or settings.LLAMACPP_TIMEOUT)
            if r.status_code == 400 and "response_format" in r.text and json_mode:
                self._json_mode = False  # some servers reject json mode - retry without it
                body.pop("response_format", None)
                r = httpx.post(self._url("/chat/completions"), json=body, headers=self._headers(),
                               timeout=timeout or settings.LLAMACPP_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            self._avail = (time.time(), False)
            raise AIError(f"{self.spec.name}: {e}") from e
        if r.status_code >= 400:
            raise ai_error(f"{self.spec.name} HTTP {r.status_code}", r.text[:300])
        try:
            return r.json()["choices"][0]["message"]
        except (KeyError, IndexError, ValueError) as e:
            raise AIError(f"{self.spec.name}: unexpected response {r.text[:200]}") from e

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        return self.chat(msgs, json_mode=json_mode).get("content") or ""

    def chat_json(self, prompt: str, system: str = ""):
        return parse_json(self.generate(prompt, system=system, json_mode=True))


def _ollama_client(spec: ProviderSpec):
    from .local import OllamaClient
    c = OllamaClient(base_url=spec.base_url or settings.OLLAMA_BASE_URL, model=spec.model or settings.OLLAMA_MODEL)
    c.name = spec.key
    if spec.source == "db":
        c.enabled_override = spec.enabled
    return c


def _anthropic_client(spec: ProviderSpec):
    from .cloud import CloudClient
    c = CloudClient("anthropic", api_key=spec.api_key, model=spec.model)
    c.name = spec.key
    return c


def client_for(spec: ProviderSpec):
    """Text client (available / generate / chat_json) for a provider."""
    if spec.kind == "ollama":
        return _ollama_client(spec)
    if spec.kind == "llamacpp":
        from .llamacpp import LlamaCppClient
        c = LlamaCppClient()
        c.name = spec.key
        return c
    if spec.kind == "anthropic":
        return _anthropic_client(spec)
    return OpenAICompatClient(spec)


# ---------------------------------------------------------------- registry
def env_providers() -> list[ProviderSpec]:
    out = []
    local_first = settings.LOCAL_AI_BACKEND
    if settings.OLLAMA_ENABLED:
        out.append(ProviderSpec("env:ollama", "Ollama (.env)", "ollama", settings.OLLAMA_BASE_URL, "",
                                settings.OLLAMA_MODEL, "local", True, 10 if local_first == "ollama" else 20,
                                preset="ollama"))
    if local_first == "llamacpp":
        from .llamacpp import base_url
        out.append(ProviderSpec("env:llamacpp", f"llama.cpp ({settings.LLAMACPP_MODE})", "llamacpp",
                                base_url() if settings.LLAMACPP_MODE != "embedded" else "", "", "", "local", True, 10,
                                preset="llamacpp"))
    if settings.OPENAI_API_KEY:
        out.append(ProviderSpec("env:openai", "OpenAI (.env)", "openai_compat", "https://api.openai.com/v1",
                                settings.OPENAI_API_KEY, settings.OPENAI_MODEL, "remote", True,
                                30 if settings.AI_CLOUD_PROVIDER == "openai" else 40, preset="openai"))
    if settings.ANTHROPIC_API_KEY:
        out.append(ProviderSpec("env:anthropic", "Anthropic (.env)", "anthropic", "https://api.anthropic.com",
                                settings.ANTHROPIC_API_KEY, settings.ANTHROPIC_MODEL, "remote", True,
                                30 if settings.AI_CLOUD_PROVIDER == "anthropic" else 40, preset="anthropic"))
    return out


def db_providers() -> list[ProviderSpec]:
    from ..storage.db import session_scope
    from ..storage.models import AIProvider
    try:
        with session_scope() as s:
            return [ProviderSpec(f"db:{p.id}", p.name, p.kind, p.base_url, p.api_key, p.model, p.trust, p.enabled,
                                 p.priority, p.supports_tools, p.context_window or 0, "db", p.preset)
                    for p in s.query(AIProvider)]
    except Exception:  # noqa: BLE001 - table may not exist yet
        return []


_cache: dict = {"ts": 0.0, "specs": []}


def all_providers(fresh: bool = False) -> list[ProviderSpec]:
    if fresh or time.time() - _cache["ts"] > 10:
        _cache.update(ts=time.time(), specs=sorted(env_providers() + db_providers(), key=lambda p: p.priority))
    return list(_cache["specs"])


def invalidate() -> None:
    _cache["ts"] = 0.0
    _clients.clear()


_clients: dict[str, object] = {}


def get_client(spec: ProviderSpec):
    sig = f"{spec.key}|{spec.base_url}|{spec.model}|{spec.api_key}|{spec.enabled}"
    c = _clients.get(sig)
    if c is None:
        c = _clients[sig] = client_for(spec)
    return c


def ordered_for(raw: bool) -> list[ProviderSpec]:
    """Raw-content tasks: local providers (+ remote only with CLOUD_ALLOW_RAW).
    Derived tasks: remote first (if routing allows), then local."""
    specs = [p for p in all_providers() if p.enabled]
    local = [p for p in specs if p.is_local]
    remote = [p for p in specs if not p.is_local]
    routing = settings.AI_ROUTING.lower()
    if routing == "local":
        return local
    if raw:
        return local + (remote if settings.CLOUD_ALLOW_RAW else [])
    return remote + local if routing in ("hybrid", "cloud") else local


def test_provider(spec: ProviderSpec) -> dict:
    t0 = time.time()
    out = {"ok": False, "models": [], "latency_ms": None, "error": None, "reply": None}
    try:
        c = client_for(spec)
        if isinstance(c, OpenAICompatClient):
            try:
                out["models"] = c.list_models()[:200]
            except Exception as e:  # noqa: BLE001
                out["models_error"] = str(e)[:200]
            if not spec.model and out["models"]:
                spec.model = out["models"][0]
                c = client_for(spec)
        reply = c.generate('Reply with the JSON object {"ok": true}.', system="You are a connectivity test.",
                           json_mode=True)
        out.update(ok=True, reply=(reply or "")[:200], model=spec.model or getattr(c, "model", ""))
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:400]
    out["latency_ms"] = int((time.time() - t0) * 1000)
    return out


def find(key: str) -> Optional[ProviderSpec]:
    return next((p for p in all_providers(fresh=True) if p.key == key), None)
