"""HTTP client over Tor SOCKS5h with safety checks and limits."""
from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import settings

logger = logging.getLogger(__name__)


class TorUnavailable(RuntimeError):
    """Raised when Tor is required but cannot be verified."""


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status_code: Optional[int] = None
    content_type: str = ""
    text: str = ""
    error: Optional[str] = None
    truncated: bool = False
    elapsed: float = 0.0
    headers: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code == 200


def proxies() -> dict:
    if not settings.TOR_ENABLED:
        return {}
    url = f"socks5h://{settings.TOR_PROXY_HOST}:{settings.TOR_PROXY_PORT}"
    return {"http": url, "https": url}


_tor_cache = {"ts": 0.0, "result": None}
_tor_lock = threading.Lock()


def tor_status(force: bool = False, max_age: float = 300) -> dict:
    """Verify that traffic actually leaves through Tor (cached)."""
    with _tor_lock:
        if not force and _tor_cache["result"] and time.time() - _tor_cache["ts"] < max_age:
            return _tor_cache["result"]
        res = {"enabled": settings.TOR_ENABLED, "proxy": f"{settings.TOR_PROXY_HOST}:{settings.TOR_PROXY_PORT}",
               "reachable": False, "is_tor": False, "exit_ip": None, "error": None}
        if not settings.TOR_ENABLED:
            res["error"] = "TOR_ENABLED=false"
        else:
            try:
                with socket.create_connection((settings.TOR_PROXY_HOST, settings.TOR_PROXY_PORT), timeout=5):
                    res["reachable"] = True
                r = requests.get(settings.TOR_CHECK_URL, proxies=proxies(), timeout=30,
                                 headers={"User-Agent": settings.USER_AGENT})
                data = r.json()
                res["is_tor"] = bool(data.get("IsTor"))
                res["exit_ip"] = data.get("IP")
            except Exception as e:  # noqa: BLE001
                res["error"] = str(e)[:300]
        _tor_cache.update(ts=time.time(), result=res)
        return res


def ensure_tor() -> None:
    """Raise TorUnavailable unless Tor is verified (when TOR_REQUIRED)."""
    if not settings.TOR_REQUIRED:
        if not settings.TOR_ENABLED:
            logger.warning("TOR_ENABLED=false and TOR_REQUIRED=false: requests go out DIRECTLY")
        return
    if not settings.TOR_ENABLED:
        raise TorUnavailable("TOR_REQUIRED=true but TOR_ENABLED=false")
    st = tor_status()
    if not st["is_tor"]:
        st = tor_status(force=True)
    if not st["is_tor"]:
        raise TorUnavailable(f"Tor not verified at {st['proxy']}: {st['error'] or 'IsTor=false'}")


def new_identity() -> tuple[bool, str]:
    """Ask the Tor control port for a new circuit (SIGNAL NEWNYM)."""
    try:
        with socket.create_connection((settings.TOR_PROXY_HOST, settings.TOR_CONTROL_PORT), timeout=10) as s:
            pw = settings.TOR_CONTROL_PASSWORD.replace("\\", "\\\\").replace('"', '\\"')
            s.sendall(f'AUTHENTICATE "{pw}"\r\n'.encode())
            if not s.recv(1024).startswith(b"250"):
                return False, "authentication failed"
            s.sendall(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(1024)
            s.sendall(b"QUIT\r\n")
            ok = resp.startswith(b"250")
            if ok:
                _tor_cache["ts"] = 0
            return ok, resp.decode(errors="replace").strip()
    except Exception as e:  # noqa: BLE001
        return False, str(e)


class TorClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": settings.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.session.proxies.update(proxies())
        retry = Retry(total=settings.MAX_RETRIES, backoff_factor=2,
                      status_forcelist=[502, 503, 504], allowed_methods=["GET", "HEAD"])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.allowed_types = [t.lower() for t in settings.list_of("ALLOWED_CONTENT_TYPES")]

    def get(self, url: str, timeout: int | None = None) -> FetchResult:
        """GET with streaming, content-type allow-list and a byte cap. Never raises."""
        timeout = timeout or settings.REQUEST_TIMEOUT
        res = FetchResult(url=url)
        t0 = time.time()
        try:
            with self.session.get(url, timeout=timeout, allow_redirects=True, stream=True) as r:
                res.status_code = r.status_code
                res.final_url = r.url
                res.headers = {k: v for k, v in r.headers.items() if k.lower() in ("server", "content-type", "last-modified")}
                ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                res.content_type = ctype
                if r.status_code != 200:
                    res.error = f"HTTP {r.status_code}"
                    return res
                if ctype and self.allowed_types and ctype not in self.allowed_types:
                    res.error = f"skipped content-type {ctype}"
                    return res
                cap = settings.MAX_RESPONSE_BYTES
                buf = bytearray()
                for chunk in r.iter_content(chunk_size=16384):
                    buf.extend(chunk)
                    if len(buf) > cap:
                        res.truncated = True
                        buf = buf[:cap]
                        break
                # requests defaults to ISO-8859-1 without a charset; most onion sites are UTF-8
                enc = (r.encoding if "charset" in (r.headers.get("Content-Type") or "").lower() else None) or "utf-8"
                try:
                    res.text = bytes(buf).decode(enc, errors="replace")
                except LookupError:
                    res.text = bytes(buf).decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001
            logger.warning("GET %s failed: %s", url, e)
            res.error = str(e)[:500]
        finally:
            res.elapsed = round(time.time() - t0, 2)
        return res
