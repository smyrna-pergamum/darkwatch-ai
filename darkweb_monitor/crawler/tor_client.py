"""HTTP client over Tor SOCKS5 proxy."""
from __future__ import annotations

import logging
import time
from typing import Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import settings

logger = logging.getLogger(__name__)


def _proxies() -> dict:
    if not settings.TOR_ENABLED:
        return {}
    host = settings.TOR_PROXY_HOST
    port = settings.TOR_PROXY_PORT
    proxy_url = f"socks5h://{host}:{port}"
    return {"http": proxy_url, "https": proxy_url}


class TorClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": settings.USER_AGENT})
        self.session.proxies.update(_proxies())
        retry = Retry(total=settings.MAX_RETRIES, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str, timeout: int = None) -> Tuple[Optional[requests.Response], Optional[str]]:
        timeout = timeout or settings.REQUEST_TIMEOUT
        try:
            r = self.session.get(url, timeout=timeout, allow_redirects=True)
            return r, None
        except Exception as e:
            logger.warning("GET %s failed: %s", url, e)
            return None, str(e)

    def check_tor(self) -> bool:
        try:
            r = self.session.get("https://check.torproject.org/api/ip", timeout=15)
            data = r.json()
            return bool(data.get("IsTor", False))
        except Exception:
            return False