"""FastAPI application."""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from config.settings import BASE_DIR, settings
from .. import __version__
from .routes import router as api_router
from .routes_ai import router as ai_router
from .routes_intel import router as intel_router
from .routes_learning import router as learning_router
from .routes_orgs import router as orgs_router
from .routes_setup import router as setup_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _dashboard_path() -> Path:
    candidates = [BASE_DIR / "dashboard" / "index.html",
                  Path(getattr(sys, "_MEIPASS", BASE_DIR)) / "dashboard" / "index.html",
                  Path(__file__).resolve().parent.parent.parent / "dashboard" / "index.html"]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


@asynccontextmanager
async def lifespan(app: FastAPI):
    from ..readiness import shutdown, startup
    startup()  # database -> Tor -> AI -> scheduler
    yield
    shutdown()


app = FastAPI(title="DarkWatch AI", version=__version__, lifespan=lifespan,
              description="AI-powered darknet monitoring & threat intelligence platform")
if settings.list_of("CORS_ORIGINS"):
    app.add_middleware(CORSMiddleware, allow_origins=settings.list_of("CORS_ORIGINS"),
                       allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-API-Key"])
app.include_router(api_router, prefix="/api")
app.include_router(ai_router, prefix="/api")
app.include_router(learning_router, prefix="/api")
app.include_router(intel_router, prefix="/api")
app.include_router(orgs_router, prefix="/api")
app.include_router(setup_router, prefix="/api")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path == "/":
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    return resp


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index():
    p = _dashboard_path()
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<h1>DarkWatch AI</h1><p>Dashboard missing.</p>"


_UI_FILES = {"intel.js": "application/javascript; charset=utf-8", "assist.js": "application/javascript; charset=utf-8",
             "ops.js": "application/javascript; charset=utf-8",
             "icon.svg": "image/svg+xml", "favicon.ico": "image/x-icon", "icon.png": "image/png"}


@app.get("/ui/{name}", include_in_schema=False)
def ui_asset(name: str):
    if name not in _UI_FILES:  # fixed allow-list: no path traversal
        return Response(status_code=404)
    p = _dashboard_path().parent / name
    try:
        return Response(p.read_bytes(), media_type=_UI_FILES[name], headers={"Cache-Control": "no-cache"})
    except FileNotFoundError:
        return Response(status_code=404)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return ui_asset("favicon.ico")


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__}
