"""Cloud AI client (OpenAI / Anthropic SDKs)."""
from __future__ import annotations

from config.settings import settings
from .base import AIError, ai_error, parse_json


class CloudClient:
    name = "cloud"

    def __init__(self, provider: str | None = None, api_key: str = "", model: str = ""):
        self.provider = (provider or settings.AI_CLOUD_PROVIDER).lower()
        self.api_key = api_key
        self.model = model
        self._client = None

    def _key(self) -> str:
        if self.api_key:
            return self.api_key
        return settings.OPENAI_API_KEY if self.provider == "openai" else settings.ANTHROPIC_API_KEY

    def _model(self) -> str:
        return self.model or (settings.OPENAI_MODEL if self.provider == "openai" else settings.ANTHROPIC_MODEL)

    def context_window(self) -> int:
        return max(settings.AI_REMOTE_CONTEXT, 16000)

    def available(self) -> bool:
        return self.provider in ("openai", "anthropic") and bool(self._key())

    def _get(self):
        if self._client is None:
            if self.provider == "openai":
                from openai import OpenAI
                self._client = OpenAI(api_key=self._key(), timeout=90)
            elif self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._key(), timeout=90)
            else:
                raise AIError(f"unknown cloud provider {self.provider}")
        return self._client

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        if not self.available():
            raise AIError("cloud provider not configured")
        try:
            client = self._get()
            if self.provider == "openai":
                msgs = ([{"role": "system", "content": system}] if system else []) + \
                       [{"role": "user", "content": prompt}]
                kw = {"model": self._model(), "messages": msgs, "temperature": 0.2}
                if json_mode:
                    kw["response_format"] = {"type": "json_object"}
                resp = client.chat.completions.create(**kw)
                return resp.choices[0].message.content or ""
            resp = client.messages.create(
                model=self._model(), max_tokens=2000, system=system or "",
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join(getattr(b, "text", "") for b in resp.content)
        except AIError:
            raise
        except Exception as e:  # noqa: BLE001
            raise ai_error(self.provider, e) from e

    def chat_json(self, prompt: str, system: str = ""):
        return parse_json(self.generate(prompt, system=system, json_mode=True))
