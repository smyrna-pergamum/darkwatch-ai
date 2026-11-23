"""GGUF model manager: upload, download (Hugging Face etc.), register a path,
activate (restarts the managed llama-server / reloads the embedded model)."""
from __future__ import annotations

import logging
import re
import struct
import threading
from pathlib import Path
from urllib.parse import urlparse

import httpx

from config.settings import settings
from ..storage.db import audit, session_scope
from ..storage.models import LocalModel

logger = logging.getLogger(__name__)
GGUF_MAGIC = b"GGUF"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class ModelError(ValueError):
    pass


def models_dir() -> Path:
    d = Path(settings.MODELS_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_filename(name: str) -> str:
    name = _SAFE.sub("_", Path(name).name).strip("._") or "model"
    return name if name.lower().endswith(".gguf") else name + ".gguf"


def is_gguf(path: str | Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == GGUF_MAGIC
    except OSError:
        return False


# ------------------------------------------------------------ GGUF header
_FMT = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}
FILE_TYPES = {0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1", 10: "Q2_K", 11: "Q3_K_S",
              12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M", 18: "Q6_K",
              19: "IQ2_XXS", 20: "IQ2_XS", 24: "IQ1_S", 25: "IQ4_NL", 26: "IQ3_S", 28: "IQ4_XS", 32: "BF16"}


def read_gguf_meta(path: str | Path, max_keys: int = 64) -> dict:
    """Read basic metadata (architecture, name, context length, quantisation)."""
    out: dict = {}
    with open(path, "rb") as f:
        if f.read(4) != GGUF_MAGIC:
            raise ModelError("not a GGUF file")
        version = struct.unpack("<I", f.read(4))[0]
        out["gguf_version"] = version
        out["tensor_count"], kv_count = struct.unpack("<QQ", f.read(16))

        def rstr():
            n = struct.unpack("<Q", f.read(8))[0]
            if n > 1 << 20:
                raise ModelError("corrupt GGUF string")
            return f.read(n).decode("utf-8", "replace")

        def rval(t):
            if t == 8:
                return rstr()
            if t == 9:
                it, n = struct.unpack("<IQ", f.read(12))
                if it == 8:
                    for _ in range(n):
                        rstr()
                else:
                    f.seek(struct.calcsize(_FMT[it]) * n, 1)
                return f"<array {n}>"
            fmt = _FMT[t]
            return struct.unpack(fmt, f.read(struct.calcsize(fmt)))[0]

        for _ in range(min(kv_count, max_keys)):
            key = rstr()
            t = struct.unpack("<I", f.read(4))[0]
            if key.startswith("tokenizer."):
                break
            val = rval(t)
            if key in ("general.architecture", "general.name", "general.size_label", "general.file_type") \
                    or key.endswith(".context_length"):
                out[key] = val
    if "general.file_type" in out:
        out["quantization"] = FILE_TYPES.get(out["general.file_type"], str(out["general.file_type"]))
    return out


# ------------------------------------------------------------ registry
def to_dict(m: LocalModel) -> dict:
    return {"id": m.id, "name": m.name, "path": m.path, "source": m.source, "url": m.url,
            "size_bytes": m.size_bytes, "status": m.status, "progress": m.progress, "error": m.error,
            "meta": m.meta or {}, "active": m.active, "created_at": m.created_at.isoformat() + "Z"}


def list_models() -> list[dict]:
    with session_scope() as s:
        return [to_dict(m) for m in s.query(LocalModel).order_by(LocalModel.id.desc())]


def _finish(model_id: int, path: Path) -> None:
    with session_scope() as s:
        m = s.get(LocalModel, model_id)
        try:
            meta = read_gguf_meta(path)
            m.meta, m.status, m.progress, m.size_bytes = meta, "ready", 1.0, path.stat().st_size
            m.name = m.name or meta.get("general.name") or path.name
        except Exception as e:  # noqa: BLE001
            m.status, m.error = "failed", f"invalid GGUF: {e}"
            if path.exists() and Path(settings.MODELS_DIR) in path.parents:
                path.unlink()


def register_path(path: str, name: str = "") -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise ModelError(f"file not found: {p}")
    if not is_gguf(p):
        raise ModelError("file is not a GGUF model")
    with session_scope() as s:
        if s.query(LocalModel).filter_by(path=str(p)).first():
            raise ModelError("model already registered")
        m = LocalModel(name=name or p.stem, path=str(p), source="path", status="ready")
        s.add(m)
        s.flush()
        mid = m.id
    _finish(mid, p)
    audit("model.register", str(p), actor="api")
    return next(x for x in list_models() if x["id"] == mid)


def save_upload(chunks, filename: str, name: str = "") -> dict:
    """Stream an upload (iterable of bytes) to MODELS_DIR, validating the magic."""
    target = models_dir() / safe_filename(filename)
    if target.exists():
        raise ModelError(f"{target.name} already exists")
    part = target.with_suffix(target.suffix + ".part")
    cap = int(settings.MODEL_MAX_UPLOAD_GB * (1 << 30))
    size, head = 0, b""
    try:
        with open(part, "wb") as f:
            for chunk in chunks:
                if len(head) < 4:
                    head += chunk[: 4 - len(head)]
                    if len(head) >= 4 and head[:4] != GGUF_MAGIC:
                        raise ModelError("upload is not a GGUF file")
                size += len(chunk)
                if size > cap:
                    raise ModelError(f"upload exceeds {settings.MODEL_MAX_UPLOAD_GB} GB")
                f.write(chunk)
        if head[:4] != GGUF_MAGIC:
            raise ModelError("upload is not a GGUF file")
        part.rename(target)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    with session_scope() as s:
        m = LocalModel(name=name or target.stem, path=str(target), source="upload", status="ready", size_bytes=size)
        s.add(m)
        s.flush()
        mid = m.id
    _finish(mid, target)
    audit("model.upload", f"{target.name} {size} bytes", actor="api")
    return next(x for x in list_models() if x["id"] == mid)


def _allowed_url(url: str) -> bool:
    p = urlparse(url)
    if p.scheme != "https":
        return False
    hosts = settings.list_of("MODEL_DOWNLOAD_HOSTS")
    host = (p.hostname or "").lower()
    return not hosts or any(host == h or host.endswith("." + h) for h in hosts)


def start_download(url: str, name: str = "", filename: str = "") -> dict:
    if not _allowed_url(url):
        raise ModelError("only https downloads from MODEL_DOWNLOAD_HOSTS are allowed")
    fname = safe_filename(filename or urlparse(url).path.rsplit("/", 1)[-1] or "model.gguf")
    target = models_dir() / fname
    if target.exists():
        raise ModelError(f"{fname} already exists")
    with session_scope() as s:
        m = LocalModel(name=name or target.stem, path=str(target), source="url", url=url,
                       status="downloading", progress=0.0)
        s.add(m)
        s.flush()
        mid = m.id
    threading.Thread(target=_download, args=(mid, url, target), daemon=True).start()
    audit("model.download", url, actor="api")
    return next(x for x in list_models() if x["id"] == mid)


def _download(model_id: int, url: str, target: Path) -> None:
    part = target.with_suffix(target.suffix + ".part")
    try:
        host = (urlparse(url).hostname or "").lower()
        headers = {"Authorization": f"Bearer {settings.HF_TOKEN}"} if settings.HF_TOKEN and (
            host.endswith("huggingface.co") or host.endswith("hf.co")) else {}
        with httpx.stream("GET", url, follow_redirects=True, timeout=60, headers=headers) as r:
            r.raise_for_status()
            if not _allowed_url(str(r.url)):
                raise ModelError(f"redirected to a disallowed host: {r.url.host}")
            total = int(r.headers.get("content-length") or 0)
            done, last = 0, 0.0
            with open(part, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    if done == 0 and chunk[:4] != GGUF_MAGIC:
                        raise ModelError("download is not a GGUF file")
                    f.write(chunk)
                    done += len(chunk)
                    if total and done / total - last >= 0.01:
                        last = done / total
                        with session_scope() as s:
                            m = s.get(LocalModel, model_id)
                            m.progress, m.size_bytes = round(last, 3), done
        part.rename(target)
        _finish(model_id, target)
    except Exception as e:  # noqa: BLE001
        logger.warning("model download failed: %s", e)
        part.unlink(missing_ok=True)
        with session_scope() as s:
            m = s.get(LocalModel, model_id)
            m.status, m.error = "failed", str(e)[:500]


def activate(model_id: int) -> dict:
    from . import llamacpp
    with session_scope() as s:
        m = s.get(LocalModel, model_id)
        if not m:
            raise ModelError("model not found")
        if m.status != "ready":
            raise ModelError("model is not ready")
        for other in s.query(LocalModel).filter(LocalModel.active.is_(True)):
            other.active = False
        m.active = True
        path = m.path
    if settings.LLAMACPP_MODE == "managed":
        llamacpp.managed.start(path)
        threading.Thread(target=llamacpp.managed.wait_ready, daemon=True).start()
    elif settings.LLAMACPP_MODE == "embedded":
        llamacpp.embedded.unload()
    audit("model.activate", path, actor="api")
    return {"ok": True, "active": model_id, "mode": settings.LLAMACPP_MODE}


def delete(model_id: int) -> dict:
    from . import llamacpp
    with session_scope() as s:
        m = s.get(LocalModel, model_id)
        if not m:
            raise ModelError("model not found")
        p = Path(m.path)
        was_active = m.active
        s.delete(m)
    owned = Path(settings.MODELS_DIR).resolve() in p.resolve().parents
    if was_active:
        llamacpp.managed.stop()
        llamacpp.embedded.unload()
    if owned:
        p.unlink(missing_ok=True)
        p.with_suffix(p.suffix + ".part").unlink(missing_ok=True)
    audit("model.delete", f"{p} (file {'deleted' if owned else 'kept - registered path'})", actor="api")
    return {"ok": True, "file_deleted": owned}


def autostart() -> None:
    """In managed mode start llama-server with the active model on boot."""
    from . import llamacpp
    if settings.LOCAL_AI_BACKEND != "llamacpp" or settings.LLAMACPP_MODE != "managed":
        return
    p = llamacpp.active_model_path()
    if p:
        try:
            llamacpp.managed.start(p)
        except Exception as e:  # noqa: BLE001
            logger.warning("llama-server autostart failed: %s", e)

