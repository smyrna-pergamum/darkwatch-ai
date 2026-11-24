"""API: start-up order / setup checklist, built-in Tor, built-in AI engine, assistant."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..storage.db import audit
from .routes import require_key

router = APIRouter(dependencies=[Depends(require_key)])


# ---------------------------------------------------------------- order / checklist
@router.get("/setup/checklist")
def setup_checklist():
    from ..readiness import boot, checklist, deferred
    return {"steps": checklist(), "boot": boot, "deferred_crawls": deferred()}


# ---------------------------------------------------------------- built-in Tor
class TorConnectIn(BaseModel):
    bridge_mode: Optional[Literal["direct", "auto", "snowflake", "obfs4", "meek", "webtunnel", "custom"]] = None
    bridges: Optional[str] = Field(default=None, max_length=20000)


@router.get("/tor/manager")
def tor_manager_status():
    from .. import tor_manager
    return tor_manager.status()


@router.post("/tor/connect")
def tor_connect(b: TorConnectIn):
    from .. import tor_manager
    from config.runtime import save
    if b.bridges is not None:
        save(TOR_BRIDGES=b.bridges.strip())
        if b.bridges.strip() and not tor_manager.custom_bridges():
            raise HTTPException(400, "no valid bridge line found (expected e.g. 'obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0')")
    try:
        st = tor_manager.start(b.bridge_mode)
    except tor_manager.TorSetupError as e:
        raise HTTPException(400, str(e)) from e
    audit("tor.connect", f"built-in Tor, bridges={b.bridge_mode or 'default'}")
    return st


@router.post("/tor/reconnect")
def tor_reconnect():
    from .. import tor_manager
    from ..crawler.tor_client import tor_status
    from config.settings import settings
    if settings.TOR_MODE == "managed" or tor_manager.state["status"] != "stopped":
        # keep the transport that worked (e.g. snowflake) instead of probing again
        st = tor_manager.start(tor_manager.state.get("transport") or settings.TOR_BRIDGE_MODE or "auto")
        audit("tor.reconnect", "built-in Tor restarted")
        return {"restarted": True, **st}
    audit("tor.reconnect", "external Tor re-checked")
    return {"restarted": False, "tor": tor_status(force=True)}


@router.post("/tor/stop")
def tor_stop():
    from .. import tor_manager
    audit("tor.stop", "built-in Tor stopped - external Tor proxy in use")
    return tor_manager.stop()


# ---------------------------------------------------------------- built-in AI engine
class EngineSetupIn(BaseModel):
    size: Optional[Literal["small", "balanced", "strong"]] = None


@router.get("/ai/engine")
def ai_engine_status():
    from ..ai import engine
    return engine.status()


@router.post("/ai/engine/setup", status_code=202)
def ai_engine_setup(b: EngineSetupIn):
    from ..ai import engine
    try:
        st = engine.setup(b.size)
    except engine.EngineError as e:
        raise HTTPException(400, str(e)) from e
    audit("ai.engine.setup", f"size={b.size or 'default'}")
    return st


# ---------------------------------------------------------------- assistant
class AskIn(BaseModel):
    question: str = Field(min_length=2, max_length=4000)


@router.get("/assistant/help")
def assistant_help(q: str = Query("", max_length=300)):
    from ..assistant import kb
    return {"topics": kb.search(q, k=4) if q else kb.TOPICS}


@router.get("/assistant/suggestions")
def assistant_suggestions(ai: bool = False):
    from ..assistant.suggest import suggestions
    return suggestions(use_ai=ai)


@router.post("/assistant/ask", status_code=202)
def assistant_ask(b: AskIn):
    from ..analyst.service import start
    try:
        return {"id": start(question=b.question, trigger="manual", agent="assistant")}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
