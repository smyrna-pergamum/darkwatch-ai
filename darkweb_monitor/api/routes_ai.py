"""API: analyst agent, AI providers, local GGUF models."""
from __future__ import annotations

from typing import Literal, Optional
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from config.settings import settings
from ..storage.db import audit, session_scope
from ..storage.models import AgentApproval, AgentEvent, AgentSession, AIProvider
from .routes import _iso, require_key

router = APIRouter(dependencies=[Depends(require_key)])


# ================================================================ analyst
class StartIn(BaseModel):
    alert_id: Optional[int] = None
    question: Optional[str] = Field(default=None, max_length=4000)


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


def _sess(r: AgentSession) -> dict:
    return {"id": r.id, "agent": r.agent, "title": r.title, "subject_type": r.subject_type,
            "subject_id": r.subject_id, "trigger": r.trigger, "status": r.status, "provider": r.provider,
            "model": r.model, "turns": r.turns, "steps": r.steps, "tool_calls": r.tool_calls, "report": r.report,
            "error": r.error, "created_at": _iso(r.created_at), "updated_at": _iso(r.updated_at)}


def _appr(a: AgentApproval) -> dict:
    return {"id": a.id, "session_id": a.session_id, "tool": a.tool, "args": a.args, "permission": a.permission,
            "reason": a.reason, "status": a.status, "result": a.result, "created_at": _iso(a.created_at),
            "decided_at": _iso(a.decided_at), "decided_by": a.decided_by}


@router.get("/analyst/status")
def analyst_status():
    from ..analyst.service import status
    from ..analyst.agent import AGENTS
    return {**status(), "agents": [{"id": a.id, "name": a.name, "description": a.description, "mode": a.mode,
                                    "steps": a.steps, "tools": a.tools} for a in AGENTS.values()]}


@router.get("/analyst/sessions")
def list_sessions(limit: int = Query(50, le=200), alert_id: Optional[int] = None, status: Optional[str] = None):
    with session_scope() as s:
        q = s.query(AgentSession).order_by(AgentSession.id.desc())
        if alert_id:
            q = q.filter_by(subject_type="alert", subject_id=alert_id)
        if status:
            q = q.filter(AgentSession.status.in_(status.split(",")))
        return [_sess(r) for r in q.limit(limit)]


@router.post("/analyst/sessions", status_code=202)
def start_session(b: StartIn):
    from ..analyst.service import start
    if not b.alert_id and not b.question:
        raise HTTPException(422, "alert_id or question required")
    try:
        return {"id": start(b.alert_id, b.question, trigger="manual")}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.get("/analyst/sessions/{sid}")
def get_session(sid: int, since: int = 0):
    with session_scope() as s:
        r = s.get(AgentSession, sid)
        if not r:
            raise HTTPException(404, "not found")
        ev = s.query(AgentEvent).filter(AgentEvent.session_id == sid, AgentEvent.seq > since).order_by(AgentEvent.seq)
        return {**_sess(r), "events": [{"seq": e.seq, "type": e.type, "payload": e.payload, "ts": _iso(e.ts)} for e in ev],
                "approvals": [_appr(a) for a in s.query(AgentApproval).filter_by(session_id=sid)]}


@router.post("/analyst/sessions/{sid}/messages", status_code=202)
def send_message(sid: int, b: MessageIn):
    from ..analyst.service import send
    try:
        send(sid, b.text)
    except KeyError as e:
        raise HTTPException(404, "not found") from e
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    return {"ok": True}


@router.post("/analyst/sessions/{sid}/cancel")
def cancel_session(sid: int):
    from ..analyst.service import cancel
    return {"ok": cancel(sid)}


@router.get("/analyst/approvals")
def list_approvals(status: str = "pending"):
    with session_scope() as s:
        return [_appr(a) for a in s.query(AgentApproval).filter(AgentApproval.status.in_(status.split(",")))
                .order_by(AgentApproval.id.desc()).limit(200)]


@router.post("/analyst/approvals/{aid}/{decision}")
def decide_approval(aid: int, decision: Literal["approve", "reject"]):
    from ..analyst.service import decide
    try:
        return decide(aid, decision == "approve", actor="api")
    except KeyError as e:
        raise HTTPException(404, "not found") from e


# ================================================================ providers
class ProviderIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    preset: str = "custom"
    kind: Optional[Literal["openai_compat", "ollama", "anthropic"]] = None
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    trust: Optional[Literal["local", "remote"]] = None
    enabled: bool = True
    priority: int = Field(default=50, ge=0, le=1000)
    supports_tools: bool = True
    context_window: int = Field(default=0, ge=0, le=2_000_000)


class ProviderPatch(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    trust: Optional[Literal["local", "remote"]] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(default=None, ge=0, le=1000)
    supports_tools: Optional[bool] = None
    context_window: Optional[int] = Field(default=None, ge=0, le=2_000_000)


class TestIn(BaseModel):
    key: Optional[str] = None
    config: Optional[ProviderIn] = None


def _spec_from_in(p: ProviderIn):
    from ..ai.providers import PRESETS, ProviderSpec, guess_trust
    pre = PRESETS.get(p.preset, PRESETS["custom"])
    base = p.base_url or pre["base_url"]
    if not base and (p.kind or pre["kind"]) != "anthropic":
        raise HTTPException(422, "base_url required")
    return ProviderSpec("test", p.name, p.kind or pre["kind"], base, p.api_key, p.model,
                        p.trust or guess_trust(base), p.enabled, p.priority, p.supports_tools, p.context_window,
                        "db", p.preset)


@router.get("/ai/presets")
def presets():
    from ..ai.providers import PRESETS
    return PRESETS


@router.get("/ai/providers")
def providers(check: bool = False):
    from ..ai.providers import all_providers, get_client, ordered_for
    out = []
    for p in all_providers(fresh=True):
        d = p.public()
        if check:
            try:
                c = get_client(p)
                d["available"] = bool(c.available())
                if d["available"]:
                    from ..ai.context import budget_for
                    d["detected_window"] = budget_for(c).window
            except Exception as e:  # noqa: BLE001
                d["available"], d["error"] = False, str(e)[:200]
        out.append(d)
    return {"providers": out, "routing": {"raw": [p.key for p in ordered_for(True)],
                                          "derived": [p.key for p in ordered_for(False)],
                                          "mode": settings.AI_ROUTING, "cloud_allow_raw": settings.CLOUD_ALLOW_RAW}}


@router.post("/ai/providers", status_code=201)
def add_provider(p: ProviderIn):
    from ..ai.providers import invalidate
    spec = _spec_from_in(p)
    with session_scope() as s:
        row = AIProvider(name=p.name, kind=spec.kind, preset=p.preset, base_url=spec.base_url, api_key=p.api_key,
                         model=p.model, trust=spec.trust, enabled=p.enabled, priority=p.priority,
                         supports_tools=p.supports_tools, context_window=p.context_window)
        s.add(row)
        s.flush()
        pid = row.id
    invalidate()
    audit("ai.provider.add", f"{p.name} {spec.base_url} trust={spec.trust}", actor="api")
    return {"key": f"db:{pid}", "trust": spec.trust}


def _db_id(key: str) -> int:
    if not key.startswith("db:"):
        raise HTTPException(400, "only providers added in the dashboard can be changed here (.env providers are read-only)")
    return int(key[3:])


@router.patch("/ai/providers/{key}")
def patch_provider(key: str, p: ProviderPatch):
    from ..ai.providers import invalidate
    with session_scope() as s:
        row = s.get(AIProvider, _db_id(key))
        if not row:
            raise HTTPException(404, "not found")
        for k, v in p.model_dump(exclude_unset=True).items():
            if k == "api_key" and v == "":
                continue  # empty = keep existing secret
            setattr(row, k, v)
    invalidate()
    audit("ai.provider.update", key, actor="api")
    return {"ok": True}


@router.delete("/ai/providers/{key}")
def delete_provider(key: str):
    from ..ai.providers import invalidate
    with session_scope() as s:
        row = s.get(AIProvider, _db_id(key))
        if not row:
            raise HTTPException(404, "not found")
        s.delete(row)
    invalidate()
    audit("ai.provider.delete", key, actor="api")
    return {"ok": True}


@router.post("/ai/providers/test")
def test_provider_ep(b: TestIn):
    from ..ai.providers import find, test_provider
    if b.config:
        spec = _spec_from_in(b.config)
        if not spec.api_key and b.key and b.key.startswith("db:"):
            existing = find(b.key)
            spec.api_key = existing.api_key if existing else ""
    elif b.key:
        spec = find(b.key)
        if not spec:
            raise HTTPException(404, "provider not found")
    else:
        raise HTTPException(422, "key or config required")
    return test_provider(spec)


@router.get("/ai/providers/{key}/models")
def provider_models(key: str):
    from ..ai.providers import OpenAICompatClient, find
    spec = find(key)
    if not spec:
        raise HTTPException(404, "provider not found")
    try:
        if spec.kind == "ollama":
            r = httpx.get(spec.base_url.rstrip("/") + "/api/tags", timeout=8)
            return sorted(m["name"] for m in r.json().get("models", []))
        if spec.kind == "openai_compat":
            return OpenAICompatClient(spec).list_models()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"could not list models: {e}") from e
    return []


# ================================================================ GGUF models
class RegisterIn(BaseModel):
    path: str
    name: str = ""


class DownloadIn(BaseModel):
    url: Optional[str] = None
    repo: Optional[str] = None
    file: Optional[str] = None
    revision: str = "main"
    name: str = ""


def _merr(fn):
    from ..ai.models import ModelError
    try:
        return fn()
    except ModelError as e:
        raise HTTPException(400, str(e)) from e


@router.get("/ai/models")
def gguf_models():
    from ..ai import llamacpp
    from ..ai.models import list_models
    return {"models": list_models(), "llamacpp": llamacpp.status(), "models_dir": settings.MODELS_DIR,
            "max_upload_gb": settings.MODEL_MAX_UPLOAD_GB, "download_hosts": settings.list_of("MODEL_DOWNLOAD_HOSTS"),
            "hf_token": bool(settings.HF_TOKEN)}


@router.post("/ai/models/register", status_code=201)
def gguf_register(b: RegisterIn):
    from ..ai.models import register_path
    return _merr(lambda: register_path(b.path, b.name))


@router.post("/ai/models/download", status_code=202)
def gguf_download(b: DownloadIn):
    from ..ai.models import start_download
    url = b.url
    if not url and b.repo and b.file:
        url = f"{settings.HF_ENDPOINT.rstrip('/')}/{b.repo}/resolve/{quote(b.revision)}/{quote(b.file)}?download=true"
    if not url:
        raise HTTPException(422, "url or repo+file required")
    return _merr(lambda: start_download(url, b.name, (b.file or "").rsplit("/", 1)[-1]))


@router.put("/ai/models/upload", status_code=201)
async def gguf_upload(request: Request, filename: str = Query(..., max_length=255), name: str = ""):
    """Raw streamed body (application/octet-stream) - no multipart dependency."""
    import asyncio
    import queue
    import threading
    from ..ai.models import ModelError, save_upload
    q: queue.Queue = queue.Queue(maxsize=64)
    out: dict = {}

    def worker():
        def chunks():
            while True:
                c = q.get()
                if c is None:
                    return
                yield c
        try:
            out["res"] = save_upload(chunks(), filename, name)
        except Exception as e:  # noqa: BLE001
            out["err"] = e
            while q.get() is not None:  # drain so the reader never blocks
                pass
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    loop = asyncio.get_running_loop()
    async for chunk in request.stream():
        if chunk:
            await loop.run_in_executor(None, q.put, chunk)
    await loop.run_in_executor(None, q.put, None)
    await loop.run_in_executor(None, t.join)
    if "err" in out:
        e = out["err"]
        raise HTTPException(400 if isinstance(e, ModelError) else 500, str(e))
    return out["res"]


@router.post("/ai/models/{mid}/activate")
def gguf_activate(mid: int):
    from ..ai.models import activate
    from ..ai.providers import invalidate
    res = _merr(lambda: activate(mid))
    invalidate()
    return res


@router.delete("/ai/models/{mid}")
def gguf_delete(mid: int):
    from ..ai.models import delete
    return _merr(lambda: delete(mid))


@router.post("/ai/llamacpp/{action}")
def llamacpp_control(action: Literal["start", "stop"]):
    from ..ai import llamacpp
    if settings.LLAMACPP_MODE != "managed":
        raise HTTPException(400, "LLAMACPP_MODE is not 'managed'")
    if action == "stop":
        llamacpp.managed.stop()
        return {"ok": True}
    p = llamacpp.active_model_path()
    if not p:
        raise HTTPException(400, "no active GGUF model")
    try:
        llamacpp.managed.start(p)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e)) from e
    return {"ok": True}


@router.get("/ai/hf/files")
def hf_files(repo: str = Query(..., pattern=r"^[\w.-]+/[\w.-]+$"), revision: str = "main"):
    """List .gguf files of a Hugging Face repo (with sizes)."""
    h = {"Authorization": f"Bearer {settings.HF_TOKEN}"} if settings.HF_TOKEN else {}
    try:
        r = httpx.get(f"{settings.HF_ENDPOINT.rstrip('/')}/api/models/{repo}/tree/{quote(revision)}",
                      params={"recursive": "true"}, headers=h, timeout=20)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Hugging Face unreachable: {e}") from e
    if r.status_code == 401:
        raise HTTPException(401, "repo is gated/private - set HF_TOKEN")
    if r.status_code == 404:
        raise HTTPException(404, "repo not found")
    r.raise_for_status()
    files = [{"file": f["path"], "size": (f.get("lfs") or {}).get("size") or f.get("size", 0)}
             for f in r.json() if f.get("type") == "file" and f["path"].lower().endswith(".gguf")]
    return sorted(files, key=lambda x: x["size"])
