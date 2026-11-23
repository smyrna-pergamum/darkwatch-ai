"""Ollama (local) client."""
from __future__ import annotations

import json
import httpx
from typing import Optional

from config.settings import settings


class OllamaClient:
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL

    def available(self) -> bool:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
        }
        if json_mode:
            payload["format"] = "json"
        try:
            r = httpx.post(f"{self.base_url}/api/generate", json=payload, timeout=300)
            r.raise_for_status()
            return r.json().get("response", "")
        except Exception as e:
            return f"[ollama error: {e}]"

    def chat_json(self, prompt: str, system: str = "") -> Optional[dict]:
        raw = self.generate(prompt, system=system, json_mode=True)
        try:
            return json.loads(raw)
        except Exception:
            # try to extract json
            import re
            m = re.search(r"\{.*\}|\[.*\]", raw, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
            return None