"""llama.cpp local AI backend.

Modes (LLAMACPP_MODE):
  server   - talk to a llama-server you run yourself (OpenAI-compatible /v1 API)
  managed  - this app starts/stops llama-server with the active GGUF model
  embedded - load the GGUF in-process with llama-cpp-python (optional)
"""
from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import threading
import time
from pathlib import Path

import httpx

from config.settings import DATA_DIR, settings
from .base import AIError, ai_error, parse_json

logger = logging.getLogger(__name__)


def base_url() -> str:
    if settings.LLAMACPP_MODE == "managed":
        return f"http://127.0.0.1:{settings.LLAMACPP_PORT}"
    return settings.LLAMACPP_BASE_URL.rstrip("/").removesuffix("/v1")


def _headers() -> dict:
    return {"Authorization": f"Bearer {settings.LLAMACPP_API_KEY}"} if settings.LLAMACPP_API_KEY else {}


def active_model_path() -> str | None:
    from ..storage.db import session_scope
    from ..storage.models import LocalModel
    try:
        with session_scope() as s:
            m = s.query(LocalModel).filter_by(active=True, status="ready").first()
            return m.path if m else None
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------ managed server
class ManagedServer:
    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.model_path: str | None = None
        self.lock = threading.Lock()
        self.log_path = DATA_DIR / "llama-server.log"

    def binary(self) -> str | None:
        b = settings.LLAMACPP_SERVER_BIN
        if os.path.isfile(b):
            return b
        from .engine import find_engine  # built-in engine in data/engine
        return find_engine() or shutil.which(b)

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, model_path: str) -> None:
        with self.lock:
            self._stop_locked()
            exe = self.binary()
            if not exe:
                raise AIError(f"llama-server binary not found ({settings.LLAMACPP_SERVER_BIN}); "
                              "use 'Set up built-in AI' (AI & Models) or set LLAMACPP_SERVER_BIN")
            cmd = [exe, "-m", model_path, "--host", "127.0.0.1", "--port", str(settings.LLAMACPP_PORT),
                   "-c", str(settings.LLAMACPP_CTX), "--jinja", "-ngl", str(settings.LLAMACPP_GPU_LAYERS)]
            if settings.LLAMACPP_THREADS:
                cmd += ["-t", str(settings.LLAMACPP_THREADS)]
            if settings.LLAMACPP_API_KEY:
                cmd += ["--api-key", settings.LLAMACPP_API_KEY]
            cmd += shlex.split(settings.LLAMACPP_EXTRA_ARGS)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            log = open(self.log_path, "ab")  # noqa: SIM115 - owned by the child process
            logger.info("starting llama-server: %s", " ".join(cmd))
            self.proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                         cwd=str(Path(exe).resolve().parent),  # finds its DLLs / .so files
                                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self.model_path = model_path

    def wait_ready(self, timeout: float = 180) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            if not self.running():
                return False
            try:
                if httpx.get(base_url() + "/health", timeout=3).status_code == 200:
                    return True
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
        return False

    def _stop_locked(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc, self.model_path = None, None

    def stop(self) -> None:
        with self.lock:
            self._stop_locked()

    def tail_log(self, n: int = 40) -> str:
        try:
            return "\n".join(Path(self.log_path).read_text(errors="replace").splitlines()[-n:])
        except OSError:
            return ""


managed = ManagedServer()


# ------------------------------------------------------------ embedded
class Embedded:
    def __init__(self):
        self.llm = None
        self.path: str | None = None
        self.lock = threading.Lock()

    def load(self, path: str):
        with self.lock:
            if self.llm is not None and self.path == path:
                return self.llm
            try:
                from llama_cpp import Llama  # optional dependency
            except ImportError as e:
                raise AIError("llama-cpp-python is not installed (pip install llama-cpp-python)") from e
            self.llm = None
            self.llm = Llama(model_path=path, n_ctx=settings.LLAMACPP_CTX, n_gpu_layers=settings.LLAMACPP_GPU_LAYERS,
                             n_threads=settings.LLAMACPP_THREADS or None, verbose=False)
            self.path = path
            return self.llm

    def unload(self):
        with self.lock:
            self.llm, self.path = None, None


embedded = Embedded()


# ------------------------------------------------------------ text client
class LlamaCppClient:
    """Same interface as OllamaClient (available / generate / chat_json)."""
    name = "llamacpp"

    def __init__(self):
        self._avail = (0.0, False)

    def context_window(self) -> int:
        if settings.LLAMACPP_MODE == "embedded":
            return settings.LLAMACPP_CTX
        from .context import detect_context_window
        return detect_context_window("llamacpp", base_url(), api_key=settings.LLAMACPP_API_KEY) or settings.LLAMACPP_CTX

    @property
    def model(self) -> str:
        p = active_model_path() if settings.LLAMACPP_MODE != "server" else None
        return Path(p).name if p else "llama-server"

    def available(self) -> bool:
        ts, val = self._avail
        if time.time() - ts < 15:
            return val
        if settings.LLAMACPP_MODE == "embedded":
            try:
                import llama_cpp  # noqa: F401
                val = active_model_path() is not None
            except ImportError:
                val = False
        else:
            if settings.LLAMACPP_MODE == "managed" and not managed.running():
                val = False
            else:
                try:
                    val = httpx.get(base_url() + "/health", headers=_headers(), timeout=3).status_code == 200
                except Exception:  # noqa: BLE001
                    val = False
        self._avail = (time.time(), val)
        return val

    def chat(self, messages: list[dict], json_mode: bool = False, tools: list | None = None) -> dict:
        """OpenAI-style chat completion; returns the raw choice message dict."""
        if settings.LLAMACPP_MODE == "embedded":
            path = active_model_path()
            if not path:
                raise AIError("no active GGUF model")
            llm = embedded.load(path)
            kw = {"messages": messages, "temperature": 0.1}
            if json_mode:
                kw["response_format"] = {"type": "json_object"}
            try:
                out = llm.create_chat_completion(**kw)
            except Exception as e:  # noqa: BLE001 - llama-cpp-python raises ValueError on overflow
                raise ai_error("llama.cpp", e) from e
            return out["choices"][0]["message"]
        body = {"messages": messages, "temperature": 0.1, "stream": False}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if tools:
            body["tools"] = tools
        try:
            r = httpx.post(base_url() + "/v1/chat/completions", json=body, headers=_headers(),
                           timeout=settings.LLAMACPP_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            self._avail = (time.time(), False)
            raise AIError(f"llama.cpp: {e}") from e
        if r.status_code >= 400:
            raise ai_error(f"llama.cpp HTTP {r.status_code}", r.text[:300])
        return r.json()["choices"][0]["message"]

    def generate(self, prompt: str, system: str = "", json_mode: bool = False) -> str:
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        return self.chat(msgs, json_mode=json_mode).get("content") or ""

    def chat_json(self, prompt: str, system: str = ""):
        return parse_json(self.generate(prompt, system=system, json_mode=True))


def status() -> dict:
    p = active_model_path()
    st = {"mode": settings.LLAMACPP_MODE, "base_url": base_url() if settings.LLAMACPP_MODE != "embedded" else None,
          "active_model": Path(p).name if p else None, "backend_selected": settings.LOCAL_AI_BACKEND == "llamacpp",
          "available": LlamaCppClient().available()}
    if settings.LLAMACPP_MODE == "managed":
        st.update(binary=managed.binary(), running=managed.running(), log_tail=managed.tail_log(15))
    if settings.LLAMACPP_MODE == "embedded":
        try:
            import llama_cpp  # noqa: F401
            st["llama_cpp_python"] = True
        except ImportError:
            st["llama_cpp_python"] = False
    return st
