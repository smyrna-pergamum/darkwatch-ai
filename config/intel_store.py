"""Intel-source settings entered in the dashboard (API keys, on/off switches,
URLs) and user-defined custom API sources.

Stored in ``data/intel_sources.json`` (file mode 0600 where the OS supports
it) and applied on top of ``.env`` at start-up. Only an allow-list of keys can
be written. Secrets are never returned to the browser - only a masked hint.
"""
from __future__ import annotations

import json
import logging
import os
import threading

from .settings import DATA_DIR, settings

logger = logging.getLogger(__name__)
STORE_FILE = DATA_DIR / "intel_sources.json"
_lock = threading.Lock()

# key -> secret?  (everything an intel source or enrichment lookup may need)
FIELDS: dict[str, bool] = {
    "HIBP_API_KEY": True, "HIBP_CHECK_DOMAINS": False,
    "INTELX_API_KEY": True, "INTELX_BASE_URL": False, "INTELX_MAX_RESULTS": False,
    "RANSOMWARE_LIVE_ENABLED": False, "RANSOMWARE_LIVE_API_KEY": True, "RANSOMWARE_LIVE_URL": False,
    "AHMIA_ENABLED": False, "AHMIA_URL": False, "AHMIA_CLEARNET_URL": False, "AHMIA_MODE": False,
    "AHMIA_MAX_RESULTS": False,
    "ONION_SEARCH_ENABLED": False, "ONION_SEARCH_ENGINES": False,
    "HUDSONROCK_ENABLED": False, "CRTSH_ENABLED": False, "CRTSH_MAX_RESULTS": False, "PSBDMP_ENABLED": False,
    "LEAKCHECK_API_KEY": True, "DEHASHED_API_KEY": True, "LEAKIX_API_KEY": True, "GITHUB_SEARCH_TOKEN": True,
    "URLSCAN_API_KEY": True, "SHODAN_API_KEY": True,
    "VIRUSTOTAL_API_KEY": True, "ABUSEIPDB_API_KEY": True, "OTX_API_KEY": True, "ABUSECH_AUTH_KEY": True,
    "GREYNOISE_API_KEY": True,
    "EXTERNAL_API_VIA_TOR": False, "SOURCES_INTERVAL_MIN": False,
}


def _read() -> dict:
    try:
        data = json.loads(STORE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict) -> None:
    STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(STORE_FILE)


def _coerce(key: str, value):
    cur = getattr(settings, key)
    if isinstance(cur, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if isinstance(cur, int):
        return int(value)
    if isinstance(cur, float):
        return float(value)
    return str(value).strip()


def load() -> dict:
    """Apply saved values to ``settings``; returns the applied keys."""
    applied = {}
    for k, v in (_read().get("settings") or {}).items():
        if k in FIELDS and hasattr(settings, k):
            try:
                setattr(settings, k, _coerce(k, v))
                applied[k] = True
            except (TypeError, ValueError):
                logger.warning("ignoring invalid intel setting %s", k)
    return applied


def save(updates: dict) -> list[str]:
    """Persist and apply. An empty string for a secret clears it."""
    bad = set(updates) - set(FIELDS)
    if bad:
        raise ValueError(f"not an intel-source setting: {', '.join(sorted(bad))}")
    with _lock:
        data = _read()
        stored = dict(data.get("settings") or {})
        for k, v in updates.items():
            if v is None:
                continue
            val = _coerce(k, v)
            setattr(settings, k, val)
            stored[k] = val
        data["settings"] = stored
        _write(data)
    return sorted(updates)


def mask(value) -> str:
    v = str(value or "")
    if not v:
        return ""
    return ("•" * 6) + (v[-4:] if len(v) > 8 else "")


def public_value(key: str):
    v = getattr(settings, key, "")
    return {"set": bool(v), "hint": mask(v)} if FIELDS.get(key) else v


# ------------------------------------------------------------ custom sources
def custom_sources() -> list[dict]:
    return [c for c in (_read().get("custom") or []) if isinstance(c, dict) and c.get("name")]


def save_custom(entry: dict) -> dict:
    with _lock:
        data = _read()
        items = [c for c in (data.get("custom") or []) if isinstance(c, dict)]
        old = next((c for c in items if c.get("name") == entry["name"]), None)
        if old and not entry.get("api_key"):
            entry["api_key"] = old.get("api_key", "")  # keep the secret when the form leaves it blank
        items = [c for c in items if c.get("name") != entry["name"]] + [entry]
        data["custom"] = items
        _write(data)
    return entry


def delete_custom(name: str) -> bool:
    with _lock:
        data = _read()
        items = [c for c in (data.get("custom") or []) if isinstance(c, dict)]
        left = [c for c in items if c.get("name") != name]
        data["custom"] = left
        _write(data)
    return len(left) != len(items)
