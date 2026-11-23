"""Central configuration via environment variables / .env."""
from __future__ import annotations

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

import sys as _sys
if getattr(_sys, "frozen", False):
    BASE_DIR = Path(_sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Tor / proxy ---
    TOR_ENABLED: bool = True
    TOR_PROXY_HOST: str = "127.0.0.1"
    TOR_PROXY_PORT: int = 9050  # 9150 for Tor Browser
    TOR_CONTROL_PORT: int = 9051
    REQUEST_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

    # --- Crawler ---
    CRAWL_DEPTH: int = 2
    CRAWL_MAX_PAGES: int = 50
    CRAWL_DELAY_SEC: float = 2.0
    ALLOWED_DOMAINS: str = ""  # comma-separated; empty = any .onion

    # --- Storage ---
    DATABASE_URL: str = f"sqlite:///{(DATA_DIR / 'monitor.db').as_posix()}"

    # --- AI (hybrid) ---
    # local (Ollama)
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:3b"
    OLLAMA_ENABLED: bool = True
    # cloud
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-5-haiku-latest"
    # routing: "local" | "cloud" | "hybrid"
    AI_ROUTING: str = "hybrid"
    # hybrid: raw content analysis -> local, summaries/triage -> cloud
    AI_CLOUD_PROVIDER: str = "openai"  # openai | anthropic

    # --- Alerts ---
    ALERT_WEBHOOK_URL: str = ""  # Discord/Slack/Telegram webhook
    ALERT_MIN_SEVERITY: str = "medium"  # low | medium | high | critical
    ALERT_CONSOLE: bool = True
    ALERT_FILE: bool = True
    ALERT_FILE_PATH: str = str(DATA_DIR / "alerts.log")

    # --- Scheduler ---
    SCHEDULE_INTERVAL_MIN: int = 60
    TARGETS_FILE: str = str(BASE_DIR / "data" / "targets.txt")

    # --- API ---
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000


settings = Settings()

# Resolve relative sqlite paths against BASE_DIR (important for frozen exe)
_db = settings.DATABASE_URL
if _db.startswith("sqlite:///") and not _db.startswith("sqlite:////"):
    _rel = _db[len("sqlite:///"):]
    if not os.path.isabs(_rel):
        settings.DATABASE_URL = f"sqlite:///{(BASE_DIR / _rel).as_posix()}"