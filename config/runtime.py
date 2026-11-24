"""Settings changed from the dashboard (built-in Tor, built-in AI engine, ...).

They are stored in ``data/runtime.json`` and applied on top of ``.env`` at
start-up, so a one-click setup survives a restart. Only an allow-list of keys
can be written - never secrets that the user did not create through the app.
"""
from __future__ import annotations

import json
import logging
import threading

from .settings import DATA_DIR, settings

logger = logging.getLogger(__name__)
RUNTIME_FILE = DATA_DIR / "runtime.json"
ALLOWED = {
    "LOCAL_AI_BACKEND", "LLAMACPP_MODE", "LLAMACPP_SERVER_BIN", "OLLAMA_MODEL",
    "TOR_MODE", "TOR_BIN", "TOR_BRIDGE_MODE", "TOR_BRIDGES", "TOR_MANAGED_SOCKS_PORT", "TOR_MANAGED_CONTROL_PORT",
}
_lock = threading.Lock()


def _read() -> dict:
    try:
        data = json.loads(RUNTIME_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load() -> dict:
    """Apply saved overrides to ``settings``; returns what was applied."""
    applied = {}
    for k, v in _read().items():
        if k in ALLOWED and hasattr(settings, k):
            try:
                setattr(settings, k, type(getattr(settings, k))(v))
                applied[k] = v
            except (TypeError, ValueError):
                logger.warning("ignoring invalid runtime setting %s=%r", k, v)
    return applied


def save(**updates) -> dict:
    bad = set(updates) - ALLOWED
    if bad:
        raise ValueError(f"not a runtime setting: {', '.join(sorted(bad))}")
    with _lock:
        data = {**_read(), **updates}
        for k, v in updates.items():
            setattr(settings, k, type(getattr(settings, k))(v))
        RUNTIME_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = RUNTIME_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(RUNTIME_FILE)
        return data


def current() -> dict:
    return {k: getattr(settings, k) for k in sorted(ALLOWED) if hasattr(settings, k)}
