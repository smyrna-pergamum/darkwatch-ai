"""Built-in Tor: download the official Tor Expert Bundle, start it, and fall back
to bridges (snowflake / obfs4 / meek / webtunnel) when the network blocks Tor.

The bundle comes from dist.torproject.org and is verified against the release's
sha256sums file before it is extracted. Built-in bridge lines are read from the
bundle's own ``pt_config.json`` (the same list Tor Browser uses).
"""
from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from pathlib import Path

import httpx

from config.settings import DATA_DIR, settings

logger = logging.getLogger(__name__)

TOR_DIR = DATA_DIR / "tor"
BRIDGE_MODES = ("direct", "auto", "snowflake", "obfs4", "meek", "webtunnel", "custom")
AUTO_ORDER = ("direct", "snowflake", "obfs4", "meek")
STALL_SEC = {"direct": 60}            # no bootstrap progress for this long -> next transport
DEFAULT_STALL_SEC = 150
_EXTERNAL = (settings.TOR_PROXY_PORT, settings.TOR_CONTROL_PORT)  # .env values, restored on stop
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class TorSetupError(RuntimeError):
    pass


# ------------------------------------------------------------------ binary
def _platform_tag() -> str:
    sysname = platform.system()
    mach = platform.machine().lower()
    arch = "aarch64" if mach in ("arm64", "aarch64") else "x86_64"
    if sysname == "Windows":
        return "windows-" + ("i686" if mach in ("x86", "i386", "i686") else "x86_64")
    if sysname == "Darwin":
        return "macos-" + arch
    return "linux-" + arch


def _exe(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def find_binary() -> str | None:
    cand = [settings.TOR_BIN] if settings.TOR_BIN else []
    cand.append(str(TOR_DIR / "tor" / _exe("tor")))
    for c in cand:
        if c and os.path.isfile(c):
            return c
    return shutil.which("tor")


def _pt_dir(tor_bin: str) -> Path:
    return Path(tor_bin).resolve().parent / "pluggable_transports"


def _version_key(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def latest_bundle(client: httpx.Client) -> tuple[str, str, str]:
    """Return (version, bundle url, expected sha256) of the newest stable bundle."""
    base = settings.TOR_DIST_URL.rstrip("/") + "/"
    listing = client.get(base).text
    versions = sorted({m for m in re.findall(r'href="(\d+(?:\.\d+)+)/"', listing)}, key=_version_key, reverse=True)
    name_tpl = "tor-expert-bundle-{tag}-{v}.tar.gz"
    tag = _platform_tag()
    for v in versions[:6]:  # a new release may not have every platform yet
        name = name_tpl.format(tag=tag, v=v)
        sums = client.get(f"{base}{v}/sha256sums-signed-build.txt")
        if sums.status_code != 200:
            continue
        for line in sums.text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == name:
                return v, f"{base}{v}/{name}", parts[0].lower()
    raise TorSetupError(f"no Tor Expert Bundle for {tag} found at {base}")


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for m in tar.getmembers():
        target = (dest / m.name).resolve()
        if dest not in target.parents and target != dest:
            raise TorSetupError(f"unsafe path in archive: {m.name}")
        if m.issym() or m.islnk():
            raise TorSetupError(f"links are not allowed in the archive: {m.name}")
    try:
        tar.extractall(dest, filter="data")
    except TypeError:  # Python < 3.12
        tar.extractall(dest)  # noqa: S202 - members validated above


def download(progress=None) -> str:
    """Download, verify and extract the Tor Expert Bundle. Returns the tor path."""
    TOR_DIR.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=60, follow_redirects=True) as c:
        version, url, sha = latest_bundle(c)
        part = TOR_DIR / "bundle.tar.gz.part"
        h = hashlib.sha256()
        with c.stream("GET", url) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length") or 0)
            done = 0
            with open(part, "wb") as f:
                for chunk in r.iter_bytes(1 << 16):
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if progress and total:
                        progress(done / total)
    if h.hexdigest() != sha:
        part.unlink(missing_ok=True)
        raise TorSetupError("downloaded Tor bundle failed the SHA-256 check - not installed")
    for sub in ("tor", "data"):
        shutil.rmtree(TOR_DIR / sub, ignore_errors=True)
    with tarfile.open(part, "r:gz") as tar:
        _safe_extract(tar, TOR_DIR)
    part.unlink(missing_ok=True)
    tor = TOR_DIR / "tor" / _exe("tor")
    if os.name != "nt":
        for p in [tor, *(_pt_dir(str(tor)).glob("*"))]:
            if p.is_file():
                p.chmod(0o755)
    (TOR_DIR / "VERSION").write_text(version, encoding="utf-8")
    logger.info("Tor Expert Bundle %s installed in %s", version, TOR_DIR)
    return str(tor)


# ------------------------------------------------------------------ bridges
def pt_config(tor_bin: str) -> dict:
    try:
        return json.loads((_pt_dir(tor_bin) / "pt_config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def custom_bridges() -> list[str]:
    raw = settings.TOR_BRIDGES.replace("|", "\n")
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if line.lower().startswith("bridge "):
            line = line[7:].strip()
        if line and not line.startswith("#") and re.fullmatch(r"[\w.:\[\]=/,+@%&?~-]+(?: [\w.:\[\]=/,+@%&?~-]+)*", line):
            out.append(line)
    return out[:50]


def bridge_lines(tor_bin: str, mode: str) -> tuple[list[str], list[str]]:
    """(Bridge lines, ClientTransportPlugin lines) for a transport mode."""
    if mode == "direct":
        return [], []
    cfg = pt_config(tor_bin)
    lines = custom_bridges() if mode == "custom" else list((cfg.get("bridges") or {}).get(mode) or [])
    if not lines:
        raise TorSetupError(f"no {mode} bridges available" + (" - paste bridge lines first" if mode == "custom" else ""))
    pt_path = str(_pt_dir(tor_bin)) + os.sep
    plugins = [p.replace("${pt_path}", pt_path) for p in (cfg.get("pluggableTransports") or {}).values()]
    return lines, plugins


# ------------------------------------------------------------------ control port
def _cookie() -> bytes:
    return (TOR_DIR / "state" / "control_auth_cookie").read_bytes()


def control(cmd: str, port: int | None = None, timeout: float = 5) -> str:
    port = port or state["control_port"] or settings.TOR_MANAGED_CONTROL_PORT
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(f"AUTHENTICATE {_cookie().hex()}\r\n".encode())
        if not s.recv(1024).startswith(b"250"):
            raise TorSetupError("control port authentication failed")
        s.sendall(cmd.encode() + b"\r\n")
        buf = b""
        while not re.search(rb"^(250|[45]\d\d) .*\r\n\Z", buf, re.M):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.sendall(b"QUIT\r\n")
        return buf.decode(errors="replace")


def bootstrap() -> tuple[int, str]:
    out = control("GETINFO status/bootstrap-phase")
    m = re.search(r"PROGRESS=(\d+)", out)
    sm = re.search(r'SUMMARY="([^"]*)"', out)
    return (int(m.group(1)) if m else 0), (sm.group(1) if sm else "")


# ------------------------------------------------------------------ process
state: dict = {"status": "stopped", "progress": 0, "summary": "", "transport": None, "error": None,
               "download": None, "socks_port": None, "control_port": None, "started_at": None, "attempts": []}
_proc: subprocess.Popen | None = None
_lock = threading.Lock()
_stop_evt = threading.Event()
_worker: threading.Thread | None = None


def _port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _free_ports() -> tuple[int, int]:
    base_s, base_c = settings.TOR_MANAGED_SOCKS_PORT, settings.TOR_MANAGED_CONTROL_PORT
    for off in range(0, 40, 2):
        if _port_free(base_s + off) and _port_free(base_c + off):
            return base_s + off, base_c + off
    raise TorSetupError("no free local ports for Tor")


def write_torrc(tor_bin: str, transport: str, socks: int, ctrl: int) -> Path:
    bridges, plugins = bridge_lines(tor_bin, transport)
    data = TOR_DIR / "state"
    data.mkdir(parents=True, exist_ok=True)
    geo = TOR_DIR / "data"
    lines = [f"SocksPort 127.0.0.1:{socks}", f"ControlPort 127.0.0.1:{ctrl}", "CookieAuthentication 1",
             f'DataDirectory "{data.as_posix()}"', "AvoidDiskWrites 1", "Log notice stdout"]
    if (geo / "geoip").exists():
        lines += [f'GeoIPFile "{(geo / "geoip").as_posix()}"', f'GeoIPv6File "{(geo / "geoip6").as_posix()}"']
    if bridges:
        lines.append("UseBridges 1")
        lines += plugins
        lines += [f"Bridge {b}" for b in bridges]
    torrc = TOR_DIR / "torrc"
    torrc.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return torrc


def _kill() -> None:
    global _proc
    if _proc and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _proc.kill()
    _proc = None


def _apply_ports(socks: int | None, ctrl: int | None) -> None:
    from .crawler import tor_client
    settings.TOR_PROXY_PORT, settings.TOR_CONTROL_PORT = (socks, ctrl) if socks else _EXTERNAL
    tor_client._tor_cache["ts"] = 0


def _try(tor_bin: str, transport: str) -> bool:
    global _proc
    socks, ctrl = _free_ports()
    torrc = write_torrc(tor_bin, transport, socks, ctrl)
    log = open(TOR_DIR / "tor.log", "ab")  # noqa: SIM115 - owned by the child
    state.update(status="connecting", transport=transport, progress=0, summary="starting", socks_port=socks,
                 control_port=ctrl, error=None)
    _proc = subprocess.Popen([tor_bin, "-f", str(torrc)], stdout=log, stderr=subprocess.STDOUT,
                             cwd=str(Path(tor_bin).parent), creationflags=_NO_WINDOW)
    last, last_change = -1, time.time()
    stall = STALL_SEC.get(transport, DEFAULT_STALL_SEC)
    while not _stop_evt.is_set():
        if _proc.poll() is not None:
            state["error"] = f"tor exited ({_proc.returncode}): {tail_log(3)}"
            return False
        try:
            pct, summary = bootstrap()
        except (OSError, TorSetupError):
            pct, summary = state["progress"], state["summary"]
        if pct != last:
            last, last_change = pct, time.time()
        state.update(progress=pct, summary=summary)
        if pct >= 100:
            return True
        if time.time() - last_change > stall:
            state["error"] = f"{transport}: stuck at {pct}% ({summary})"
            return False
        _stop_evt.wait(1)
    return False


def _run(mode: str) -> None:
    try:
        tor_bin = find_binary()
        if not tor_bin:
            state.update(status="downloading", summary="downloading Tor from torproject.org", download=0.0)
            tor_bin = download(lambda p: state.update(download=round(p, 3)))
            state["download"] = 1.0
        order = AUTO_ORDER if mode == "auto" else (mode,)
        for transport in order:
            if _stop_evt.is_set():
                break
            try:
                ok = _try(tor_bin, transport)
            except TorSetupError as e:
                state["error"], ok = str(e), False
            state["attempts"].append({"transport": transport, "ok": ok, "error": state["error"]})
            if ok:
                state.update(status="connected", started_at=time.time(), error=None)
                _apply_ports(state["socks_port"], state["control_port"])
                logger.info("built-in Tor connected via %s on 127.0.0.1:%s", transport, state["socks_port"])
                return
            _kill()
        state.update(status="stopped" if _stop_evt.is_set() else "failed")
        if not _stop_evt.is_set() and not state["error"]:
            state["error"] = "could not connect"
    except Exception as e:  # noqa: BLE001
        logger.warning("built-in Tor failed: %s", e)
        _kill()
        state.update(status="failed", error=str(e)[:400])


def start(mode: str | None = None, persist: bool = True) -> dict:
    """Start (or restart) the built-in Tor in the background."""
    global _worker
    mode = mode or settings.TOR_BRIDGE_MODE or "auto"
    if mode not in BRIDGE_MODES:
        raise TorSetupError(f"bridge mode must be one of {', '.join(BRIDGE_MODES)}")
    stop(persist=False)
    with _lock:
        _stop_evt.clear()
        state.update(status="starting", progress=0, summary="", error=None, attempts=[], transport=None)
        if persist:
            from config.runtime import save
            save(TOR_MODE="managed", TOR_BRIDGE_MODE=mode)
        _worker = threading.Thread(target=_run, args=(mode,), daemon=True, name="tor-manager")
        _worker.start()
    return status()


def stop(persist: bool = True) -> dict:
    _stop_evt.set()
    w = _worker
    if w and w.is_alive() and w is not threading.current_thread():
        w.join(timeout=15)
    with _lock:
        _kill()
        _apply_ports(None, None)
        state.update(status="stopped", progress=0, summary="", socks_port=None, control_port=None)
        if persist:
            from config.runtime import save
            save(TOR_MODE="external")
    return status()


def new_identity() -> tuple[bool, str]:
    if state["status"] != "connected":
        return False, "built-in Tor is not connected"
    try:
        out = control("SIGNAL NEWNYM")
        return out.startswith("250"), out.strip()
    except (OSError, TorSetupError) as e:
        return False, str(e)


def running() -> bool:
    return _proc is not None and _proc.poll() is None


def tail_log(n: int = 20) -> str:
    try:
        return "\n".join((TOR_DIR / "tor.log").read_text(errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def status() -> dict:
    tor_bin = find_binary()
    version = None
    try:
        version = (TOR_DIR / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    available = ["direct", "auto"] + [m for m in ("snowflake", "obfs4", "meek", "webtunnel")
                                       if tor_bin and (pt_config(tor_bin).get("bridges") or {}).get(m)] + ["custom"]
    return {**state, "attempts": list(state["attempts"]), "mode": settings.TOR_MODE, "running": running(),
            "binary": tor_bin, "bundle_version": version, "bridge_mode": settings.TOR_BRIDGE_MODE,
            "bridge_modes": available, "custom_bridges": len(custom_bridges()), "log_tail": tail_log(8)}


def autostart() -> None:
    if settings.TOR_MODE == "managed":
        try:
            start(settings.TOR_BRIDGE_MODE, persist=False)
        except Exception as e:  # noqa: BLE001
            logger.warning("built-in Tor autostart failed: %s", e)


atexit.register(_kill)
