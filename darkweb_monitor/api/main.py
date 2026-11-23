"""FastAPI application."""
from __future__ import annotations

import logging
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
from .routes import router as api_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DarkWeb Monitor", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(api_router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
def index():
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent.parent / "dashboard" / "index.html"
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<h1>DarkWeb Monitor</h1><p>Dashboard missing.</p>"


@app.get("/health")
def health():
    from .routes import _ai_status
    return {"status": "ok", "ai": _ai_status()}