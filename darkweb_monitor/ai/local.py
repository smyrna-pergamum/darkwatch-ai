"""Ollama (local) client."""
from __future__ import annotations

import time

import httpx

from config.settings import settings
from .base import AIError, ai_error, parse_json


class OllamaClient:
    name = "ollama"

    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL
        self._avail = (0.0, False)
        self.enabled_override = None

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
            val = r.status_code == 200
        except Exception:  # noqa: BLE001
            val = False
        self._avail = (time.time(), val)
        return val

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
