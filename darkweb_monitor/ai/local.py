"""Ollama (local) client."""
from __future__ import annotations

import logging
import time

import httpx

from config.settings import settings
from .base import AIError, ai_error, parse_json

logger = logging.getLogger(__name__)


_SKIP = ("embed", "bge", "minilm", "nomic", "rerank", "vision", "llava", "whisper")
_PREFER = ("qwen", "llama", "gemma", "mistral", "phi", "granite", "deepseek")


def pick_model(names: list[str]) -> str | None:
    """Best general chat model among the installed ones (no embedders / coders first)."""
    def score(n: str) -> tuple:
        low = n.lower()
        return (any(k in low for k in _PREFER), "coder" not in low and "code" not in low, "uncensored" not in low)
    usable = [n for n in names if not any(k in n.lower() for k in _SKIP)]
    return max(usable, key=score) if usable else None


class OllamaClient:
    name = "ollama"

    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL
        self._avail = (0.0, False)
        self.enabled_override = None
        self.missing: str | None = None
        self.substituted: tuple[str, str] | None = None

    def context_window(self) -> int:
        from .context import detect_context_window
        n = detect_context_window("ollama", self.base_url, self.model)
        return min(n, settings.OLLAMA_NUM_CTX) if n else settings.OLLAMA_NUM_CTX

    def available(self) -> bool:
        if self.enabled_override is False or (self.enabled_override is None and not settings.OLLAMA_ENABLED):
            return False
        ts, val = self._avail
        if time.time() - ts < 30:
            return val
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=4)
            val = r.status_code == 200 and self._resolve_model([m.get("name", "") for m in r.json().get("models") or []])
        except Exception:  # noqa: BLE001
            val = False
        self._avail = (time.time(), val)
        return val

    def _resolve_model(self, installed: list[str]) -> bool:
        """The configured model must be pulled. If it is not, fall back to the
        best installed chat model instead of failing every call with HTTP 404."""
        names = [n for n in installed if n]
        if not names:
            self.missing = f"no model pulled in Ollama (run: ollama pull {self.model})"
            return False
        if self.model in names or f"{self.model}:latest" in names:
            self.missing = None
            return True
        best = pick_model(names)
        if not best:
            self.missing = f"model '{self.model}' not found in Ollama"
            return False
        logger.warning("Ollama model %s is not installed - using %s instead", self.model, best)
        self.missing = None
        self.substituted = (self.model, best)
        self.model = best
        if settings.OLLAMA_MODEL == self.substituted[0]:
            settings.OLLAMA_MODEL = best
        return True

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        payload = {"model": self.model, "prompt": prompt, "system": system, "stream": False,
                   "options": {"temperature": 0.2, "num_ctx": settings.OLLAMA_NUM_CTX}}
        if json_mode:
            payload["format"] = "json"
        try:
            r = httpx.post(f"{self.base_url}/api/generate", json=payload, timeout=settings.OLLAMA_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            self._avail = (time.time(), False)
            raise AIError(f"ollama: {e}") from e
        if r.status_code >= 400:
            raise ai_error(f"ollama HTTP {r.status_code}", r.text[:300])
        d = r.json()
        # Ollama silently truncates over-long prompts; treat that as an overflow
        if d.get("prompt_eval_count") and d["prompt_eval_count"] >= settings.OLLAMA_NUM_CTX - 8:
            raise AIError("ollama: prompt filled the whole context window (truncated)", "CONTEXT_OVERFLOW")
        return d.get("response", "")

    def chat_json(self, prompt: str, system: str = ""):
        return parse_json(self.generate(prompt, system=system, json_mode=True))
