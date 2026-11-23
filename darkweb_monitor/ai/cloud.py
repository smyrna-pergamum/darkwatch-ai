"""Cloud AI client (OpenAI / Anthropic)."""
from __future__ import annotations

import json
import re
from typing import Optional

from config.settings import settings


class CloudClient:
    def __init__(self):
        self.provider = settings.AI_CLOUD_PROVIDER
        self._openai = None
        self._anthropic = None

    def available(self) -> bool:
        if self.provider == "openai":
            return bool(settings.OPENAI_API_KEY)
        if self.provider == "anthropic":
            return bool(settings.ANTHROPIC_API_KEY)
        return False

    def _openai_client(self):
        if self._openai is None:
            from openai import OpenAI
            self._openai = OpenAI(api_key=settings.OPENAI_API_KEY)
        return self._openai

    def _anthropic_client(self):
        if self._anthropic is None:
            import anthropic
            self._anthropic = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        return self._anthropic

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        try:
            if self.provider == "openai":
                client = self._openai_client()
                msgs = []
                if system:
                    msgs.append({"role": "system", "content": system})
                msgs.append({"role": "user", "content": prompt})
                kwargs = {"model": settings.OPENAI_MODEL, "messages": msgs, "temperature": 0.2}
                if json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content or ""
            if self.provider == "anthropic":
                client = self._anthropic_client()
                resp = client.messages.create(
                    model=settings.ANTHROPIC_MODEL,
                    max_tokens=2000,
                    system=system or "",
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(b.text for b in resp.content if getattr(b, "text", None))
        except Exception as e:
            return f"[cloud error: {e}]"
        return ""

    def chat_json(self, prompt: str, system: str = "") -> Optional[dict | list]:
        raw = self.generate(prompt, system=system, json_mode=True)
        try:
            return json.loads(raw)
        except Exception:
            m = re.search(r"\{.*\}|\[.*\]", raw, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
            return None