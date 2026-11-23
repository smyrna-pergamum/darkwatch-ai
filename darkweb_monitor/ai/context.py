"""Context budgeting for small local models.

* ``estimate_tokens`` - conservative token estimate (no tokenizer needed)
* ``ContextBudget``   - how much input text fits a provider's window after
                        reserving room for the prompt template and the reply
* ``chunk_text``      - split text on paragraph / line / sentence boundaries
                        into pieces that fit the budget (with overlap)
* ``is_context_overflow`` - recognise "prompt too long" errors from any
                        provider (patterns adapted from opencode)
* ``detect_context_window`` - ask llama.cpp / Ollama / LM Studio for n_ctx
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

import httpx

from config.settings import settings

# ~3.2 chars/token is conservative for mixed English / code / non-Latin text
CHARS_PER_TOKEN = 3.2


def estimate_tokens(text: str) -> int:
    return int(len(text or "") / CHARS_PER_TOKEN) + 1


def tokens_to_chars(tokens: int) -> int:
    return max(200, int(tokens * CHARS_PER_TOKEN))


@dataclass
class ContextBudget:
    window: int                 # model context window in tokens
    reserve_output: int = 1024  # room for the reply
    overhead: int = 600         # system prompt + template + instructions

    @property
    def input_tokens(self) -> int:
        return max(256, self.window - self.reserve_output - self.overhead)

    @property
    def input_chars(self) -> int:
        return tokens_to_chars(self.input_tokens)

    def shrink(self, factor: float = 0.5) -> "ContextBudget":
        """Smaller budget after an overflow error (adaptive recovery)."""
        return ContextBudget(max(512, int(self.window * factor)), self.reserve_output, self.overhead)


_SPLITTERS = [re.compile(r"\n\s*\n"), re.compile(r"\n"), re.compile(r"(?<=[.!?])\s+"), re.compile(r"\s+")]


def chunk_text(text: str, max_chars: int, overlap: int = 200, max_chunks: int = 64) -> list[str]:
    """Split ``text`` into <= max_chars pieces at natural boundaries."""
    text = text or ""
    if len(text) <= max_chars:
        return [text]
    overlap = min(overlap, max_chars // 4)

    def split(piece: str, level: int) -> list[str]:
        if len(piece) <= max_chars:
            return [piece]
        if level >= len(_SPLITTERS):
            return [piece[i:i + max_chars] for i in range(0, len(piece), max_chars)]
        parts = [p for p in _SPLITTERS[level].split(piece) if p.strip()]
        if len(parts) <= 1:
            return split(piece, level + 1)
        out: list[str] = []
        for p in parts:
            out.extend(split(p, level + 1) if len(p) > max_chars else [p])
        return out

    units = split(text, 0)
    chunks, cur = [], ""
    for u in units:
        if cur and len(cur) + len(u) + 1 > max_chars:
            chunks.append(cur)
            tail = cur[-overlap:] if overlap else ""
            cur = (tail + "\n" + u) if tail and len(tail) + len(u) + 1 <= max_chars else u
        else:
            cur = (cur + "\n" + u) if cur else u
    if cur:
        chunks.append(cur)
    if len(chunks) > max_chunks:  # bound cost: keep the beginning and end, sample the middle
        keep = max_chunks
        idx = sorted({0, len(chunks) - 1, *[round(i * (len(chunks) - 1) / (keep - 1)) for i in range(keep)]})
        chunks = [chunks[i] for i in idx][:keep]
    return chunks


_OVERFLOW = [
    r"context[_ ]length[_ ]exceeded", r"maximum context length", r"context window (?:exceeds|exceeded)",
    r"exceeds? (?:the )?(?:model'?s? )?context", r"too large for model with \d+ maximum context length",
    r"prompt (?:is )?too long", r"prompt exceeds max length", r"input length.*exceeds.*context length",
    r"exceeded model token limit", r"token limit exceeded", r"too many tokens", r"request_too_large",
    r"the request exceeds the available context size", r"exceed_context_size_error",
    r"prompt has [\d,]+ tokens?, but the configured context size is", r"n_ctx", r"context size has been exceeded",
    r"input (?:is )?too long", r"model_context_window_exceeded", r"payload too large", r"request entity too large",
]
_OVERFLOW_RE = re.compile("|".join(_OVERFLOW), re.IGNORECASE)
_EXCLUDE_RE = re.compile(r"rate limit|too many requests|max[_ ]tokens must be less than|please wait", re.IGNORECASE)


def is_context_overflow(message: str) -> bool:
    m = str(message or "")
    return bool(_OVERFLOW_RE.search(m)) and not _EXCLUDE_RE.search(m)


# ------------------------------------------------------------ window detection
_window_cache: dict[str, tuple[float, int]] = {}


def detect_context_window(kind: str, base_url: str, model: str = "", api_key: str = "") -> int | None:
    """Best-effort n_ctx discovery. Returns None when unknown."""
    key = f"{kind}|{base_url}|{model}"
    hit = _window_cache.get(key)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    n = None
    h = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    root = re.sub(r"/v1/?$", "", (base_url or "").rstrip("/"))
    try:
        if kind in ("llamacpp", "openai_compat"):
            r = httpx.get(root + "/props", headers=h, timeout=3)  # llama-server
            if r.status_code == 200:
                d = r.json()
                n = (d.get("default_generation_settings") or {}).get("n_ctx") or d.get("n_ctx")
            if not n and model:  # LM Studio REST API
                r = httpx.get(f"{root}/api/v0/models/{model}", headers=h, timeout=3)
                if r.status_code == 200:
                    d = r.json()
                    n = d.get("loaded_context_length") or d.get("max_context_length")
        if kind == "ollama" and model:
            r = httpx.post(root + "/api/show", json={"model": model}, timeout=5)
            if r.status_code == 200:
                d = r.json()
                for k, v in (d.get("model_info") or {}).items():
                    if k.endswith(".context_length"):
                        n = int(v)
                m = re.search(r"num_ctx\s+(\d+)", d.get("parameters") or "")
                if m:
                    n = int(m.group(1))
                elif n:
                    # Ollama serves 2048-4096 tokens unless num_ctx is raised
                    n = min(n, settings.OLLAMA_NUM_CTX or 4096)
    except Exception:  # noqa: BLE001
        n = None
    if n:
        _window_cache[key] = (time.time(), int(n))
    return int(n) if n else None


def budget_for(client) -> ContextBudget:
    """ContextBudget for a text client (OllamaClient / LlamaCppClient / OpenAICompatClient / CloudClient)."""
    window = getattr(client, "context_window", None)
    if callable(window):
        window = window()
    return ContextBudget(int(window or settings.AI_DEFAULT_CONTEXT), settings.AI_RESERVE_OUTPUT_TOKENS)
