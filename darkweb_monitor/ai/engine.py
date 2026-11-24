"""Built-in AI engine: one-click (or automatic) local AI with llama.cpp.

setup() runs in the background, in order:
  1. engine  - download the official llama.cpp build for this OS (GitHub release,
               SHA-256 checked against the release digest) unless one is installed
  2. model   - download the recommended GGUF from Hugging Face (or reuse one)
  3. switch  - LOCAL_AI_BACKEND=llamacpp, LLAMACPP_MODE=managed (saved to data/runtime.json)
  4. start   - activate the model, start llama-server, wait until it answers
"""
from __future__ import annotations

import hashlib
import logging
import os
import platform
import shutil
import sys
import tarfile
import threading
import time
import zipfile
from pathlib import Path

import httpx

from config.settings import DATA_DIR, settings

logger = logging.getLogger(__name__)
ENGINE_DIR = DATA_DIR / "engine"
CATALOG = {
    "small": {"label": "Small - Qwen2.5 1.5B Instruct (Q4_K_M, ~1.1 GB, 4 GB RAM)",
              "url": "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf",
              "name": "Qwen2.5 1.5B Instruct", "size_gb": 1.1},
    "balanced": {"label": "Balanced - Qwen2.5 3B Instruct (Q4_K_M, ~2.1 GB, 6 GB RAM)",
                 "url": "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/qwen2.5-3b-instruct-q4_k_m.gguf",
                 "name": "Qwen2.5 3B Instruct", "size_gb": 2.1},
    "strong": {"label": "Strong - Qwen2.5 7B Instruct (Q4_K_M, ~4.7 GB, 10 GB RAM)",
               "url": "https://huggingface.co/bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/Qwen2.5-7B-Instruct-Q4_K_M.gguf",
               "name": "Qwen2.5 7B Instruct", "size_gb": 4.7},
}
STEPS = ("engine", "model", "switch", "start")
state: dict = {"status": "idle", "step": None, "progress": 0.0, "detail": "", "error": None, "model": None,
               "started_at": None, "finished_at": None}
_lock = threading.Lock()


class EngineError(RuntimeError):
    pass


# ------------------------------------------------------------------ engine binary
def _exe(name: str) -> str:
    return name + (".exe" if os.name == "nt" else "")


def asset_patterns() -> list[str]:
    sysname, mach = platform.system(), platform.machine().lower()
    arm = mach in ("arm64", "aarch64")
    if sysname == "Windows":
        return ["-bin-win-cpu-arm64.zip"] if arm else ["-bin-win-cpu-x64.zip"]
    if sysname == "Darwin":
        return ["-bin-macos-arm64.tar.gz", "-bin-macos-arm64.zip"] if arm else ["-bin-macos-x64.tar.gz", "-bin-macos-x64.zip"]
    return (["-bin-ubuntu-arm64.tar.gz", "-bin-ubuntu-vulkan-arm64.tar.gz"] if arm
            else ["-bin-ubuntu-x64.tar.gz", "-bin-ubuntu-x64.zip"])


def find_engine() -> str | None:
    b = settings.LLAMACPP_SERVER_BIN
    if b and os.path.isfile(b):
        return b
    if ENGINE_DIR.exists():
        found = sorted(ENGINE_DIR.rglob(_exe("llama-server")), key=lambda p: p.stat().st_mtime, reverse=True)
        if found:
            return str(found[0])
    return shutil.which(b or "llama-server")


def pick_release(releases: list[dict]) -> tuple[str, dict]:
    pats = asset_patterns()
    for rel in releases:
        for pat in pats:
            for a in rel.get("assets") or []:
                if a.get("name", "").endswith(pat) and a.get("name", "").startswith("llama-"):
                    return rel.get("tag_name", ""), a
    raise EngineError(f"no llama.cpp build for this platform ({', '.join(pats)})")


def _extract(archive: Path, dest: Path) -> None:
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            for n in z.namelist():
                if dest not in (dest / n).resolve().parents and (dest / n).resolve() != dest:
                    raise EngineError(f"unsafe path in archive: {n}")
            z.extractall(dest)
        return
    with tarfile.open(archive, "r:gz") as t:
        for m in t.getmembers():
            if dest not in (dest / m.name).resolve().parents and (dest / m.name).resolve() != dest:
                raise EngineError(f"unsafe path in archive: {m.name}")
        try:
            t.extractall(dest, filter="tar")  # keeps the .so/.dylib symlinks inside dest
        except TypeError:
            t.extractall(dest)  # noqa: S202 - members validated above


def install_engine(progress=None) -> str:
    ENGINE_DIR.mkdir(parents=True, exist_ok=True)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "DarkWatch-AI"}
    with httpx.Client(timeout=60, follow_redirects=True, headers=headers) as c:
        r = c.get(settings.LLAMACPP_RELEASES_API)
        r.raise_for_status()
        tag, asset = pick_release(r.json())
        part = ENGINE_DIR / (asset["name"] + ".part")
        h = hashlib.sha256()
        with c.stream("GET", asset["browser_download_url"]) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length") or asset.get("size") or 0)
            done = 0
            with open(part, "wb") as f:
                for chunk in resp.iter_bytes(1 << 16):
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if progress and total:
                        progress(done / total)
    digest = (asset.get("digest") or "").lower()
    if digest.startswith("sha256:") and digest[7:] != h.hexdigest():
        part.unlink(missing_ok=True)
        raise EngineError("llama.cpp download failed the SHA-256 check - not installed")
    archive = part.with_name(asset["name"])
    part.replace(archive)
    dest = ENGINE_DIR / (tag or "llama.cpp")
    shutil.rmtree(dest, ignore_errors=True)
    try:
        _extract(archive, dest)
    finally:
        archive.unlink(missing_ok=True)
    found = sorted(dest.rglob(_exe("llama-server")))
    if not found:
        raise EngineError("llama-server not found in the downloaded build")
    exe = found[0]
    if os.name != "nt":
        for p in exe.parent.iterdir():
            if p.is_file() and not p.suffix:
                p.chmod(0o755)
    from config.runtime import save
    save(LLAMACPP_SERVER_BIN=str(exe))
    logger.info("llama.cpp %s installed: %s", tag, exe)
    return str(exe)


# ------------------------------------------------------------------ model
def _ready_model_id() -> int | None:
    from ..storage.db import session_scope
    from ..storage.models import LocalModel
    with session_scope() as s:
        m = (s.query(LocalModel).filter_by(active=True, status="ready").first()
             or s.query(LocalModel).filter_by(status="ready").order_by(LocalModel.id.desc()).first())
        return m.id if m else None


def _download_model(size: str) -> int:
    from . import models
    from ..storage.db import session_scope
    from ..storage.models import LocalModel
    item = CATALOG[size]
    fname = models.safe_filename(item["url"].rsplit("/", 1)[-1])
    with session_scope() as s:
        m = s.query(LocalModel).filter(LocalModel.path.like(f"%{fname}")).order_by(LocalModel.id.desc()).first()
        existing = (m.id, m.status) if m else None
    if existing and existing[1] == "ready":
        return existing[0]
    if existing and existing[1] == "downloading":
        mid = existing[0]
    else:
        if existing:  # failed earlier - retry cleanly
            models.delete(existing[0])
        mid = models.start_download(item["url"], name=item["name"])["id"]
    while True:
        with session_scope() as s:
            m = s.get(LocalModel, mid)
            st, prog, err = m.status, m.progress or 0.0, m.error
        state.update(progress=round(prog, 3), detail=f"{item['name']}: {prog * 100:.0f}%")
        if st == "ready":
            return mid
        if st == "failed":
            raise EngineError(f"model download failed: {err}")
        time.sleep(2)


# ------------------------------------------------------------------ setup flow
def _run(size: str) -> None:
    from . import llamacpp, models, providers
    from config.runtime import save
    try:
        state.update(step="engine", progress=0.0, detail="checking llama.cpp")
        if not find_engine():
            state["detail"] = "downloading llama.cpp"
            install_engine(lambda p: state.update(progress=round(p, 3)))
        state.update(step="model", progress=0.0, detail="checking model")
        mid = _ready_model_id() or _download_model(size)
        state.update(step="switch", progress=1.0, detail="switching to the built-in engine")
        save(LOCAL_AI_BACKEND="llamacpp", LLAMACPP_MODE="managed", LLAMACPP_SERVER_BIN=find_engine() or "")
        state.update(step="start", detail="starting llama-server")
        models.activate(mid)
        if not llamacpp.managed.wait_ready(300):
            raise EngineError("llama-server did not start: " + (llamacpp.managed.tail_log(5) or "no log"))
        providers.invalidate()
        state.update(status="ready", detail="built-in AI is running", finished_at=time.time(), model=mid)
        logger.info("built-in AI engine ready")
    except Exception as e:  # noqa: BLE001
        logger.warning("built-in AI setup failed: %s", e)
        state.update(status="failed", error=str(e)[:500], finished_at=time.time())


def setup(size: str | None = None) -> dict:
    size = size or settings.AI_DEFAULT_MODEL
    if size not in CATALOG:
        raise EngineError(f"model size must be one of {', '.join(CATALOG)}")
    with _lock:
        if state["status"] == "running":
            return status()
        state.update(status="running", step=None, progress=0.0, error=None, detail="", started_at=time.time(),
                     finished_at=None, model=None, size=size)
        threading.Thread(target=_run, args=(size,), daemon=True, name="ai-engine-setup").start()
    return status()


def auto_setup_enabled() -> bool:
    v = str(settings.AI_AUTO_SETUP).lower()
    return v in ("1", "true", "yes") or (v == "auto" and bool(getattr(sys, "frozen", False)))


def maybe_auto_setup() -> bool:
    """Start setup when no local AI is usable (called once at start-up)."""
    if not auto_setup_enabled():
        return False
    from .router import get_router
    try:
        if get_router().available("page"):
            return False
    except Exception:  # noqa: BLE001
        pass
    setup()
    return True


def status() -> dict:
    from . import llamacpp
    return {**state, "steps": list(STEPS), "engine": find_engine(), "catalog": CATALOG,
            "default_size": settings.AI_DEFAULT_MODEL, "backend": settings.LOCAL_AI_BACKEND,
            "llamacpp_mode": settings.LLAMACPP_MODE, "server_running": llamacpp.managed.running(),
            "auto_setup": auto_setup_enabled()}
