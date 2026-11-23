# DarkWeb Monitor

Open-source, self-hosted **dark web / .onion monitoring** platform with a **hybrid AI agent**
(local Ollama + cloud OpenAI/Anthropic). Crawls Tor hidden services, extracts IOCs,
analyzes & summarizes content with AI, raises alerts, and exposes a dashboard.

Built as a working local-dev implementation inspired by the SOC-DarkWatch blueprint
(governance, phased rollout, evidence) and augmented with an AI agent layer.

## Features
- Tor SOCKS5 proxy crawling (depth-limited, rate-limited, .onion-aware)
- Regex + AI IOC extraction (IP, email, hash, URL, .onion, crypto addresses)
- Hybrid AI agent: local Ollama for sensitive raw content, cloud (OpenAI/Anthropic) for summaries/triage
- Content analysis: summary, category, severity, keyword watchlist
- Post-crawl **run-level AI summary** (risk level, key findings, recommendations)
- Alerting: console, file, webhook (Discord/Slack/Telegram)
- SQLite storage (SQLAlchemy) — swap to Postgres via `DATABASE_URL`
- FastAPI REST API + web dashboard (overview charts, pages, IOCs, alerts, run summaries)
- APScheduler recurring crawls
- CLI: init / status / crawl / serve

## Quick start (local dev)
```bash
cd darkweb-monitor
cp .env.example .env
# edit .env: set TOR_PROXY_PORT (9050 tor daemon / 9150 Tor Browser), AI keys, etc.

# install deps
pip install -r requirements.txt

# Tor setup (Windows): install Tor Browser or Tor Expert Bundle
# Tor Browser exposes SOCKS5 on 127.0.0.1:9150 when running.
# Set TOR_PROXY_PORT=9150 in .env accordingly.

# Ollama (local AI): https://ollama.com  ->  ollama pull llama3.2

# init db
python -m darkweb_monitor.cli init

# crawl one target
python -m darkweb_monitor.cli crawl https://example.onion --keywords "leak,brand" --depth 1

# run API + dashboard
python -m darkweb_monitor.cli serve
# open http://127.0.0.1:8000
```

## Tor proxy
The crawler uses SOCKS5h (remote DNS) via PySocks/requests. Ensure Tor is running:
- Tor daemon: `tor` (SOCKS 9050)
- Tor Browser: launch it, SOCKS 9150

Verify: `GET http://127.0.0.1:8000/api/status` shows tor proxy.

## AI routing
`AI_ROUTING` = `local` | `cloud` | `hybrid`.
- hybrid (default): raw content analysis -> local (privacy), summaries/triage -> cloud if keys present.
- Falls back gracefully if a provider is unavailable.

## Windows release (no Python needed)

Use `DarkWebMonitor-windows-release.zip` (or rebuild from source with the PyInstaller
command below). Extract it anywhere, then from the extracted folder:

```cmd
DarkWebMonitor.exe init
DarkWebMonitor.exe status
DarkWebMonitor.exe serve --port 8802
```

Open `http://127.0.0.1:8802` in your browser. The `.env` file in the folder is
preconfigured with a **relative** database path (`sqlite:///data/monitor.db`),
so the release is portable — copy the whole folder anywhere and the database is
created under its own `data/` directory.

To override settings, edit `.env` (Tor port, Ollama model, API keys, alerts, etc.).

Rebuild from source:

```bash
python -m PyInstaller --noconfirm --onedir --name DarkWebMonitor --console \
  --add-data "dashboard;dashboard" --add-data ".env.example;." \
  --hidden-import uvicorn.logging --hidden-import uvicorn.loops \
  --hidden-import uvicorn.loops.auto --hidden-import uvicorn.protocols \
  --hidden-import uvicorn.protocols.http --hidden-import uvicorn.protocols.http.auto \
  --hidden-import uvicorn.protocols.websockets --hidden-import uvicorn.protocols.websockets.auto \
  --hidden-import uvicorn.lifespan --hidden-import uvicorn.lifespan.on \
  --hidden-import sqlalchemy.dialects.sqlite \
  --exclude-module PyQt5 --exclude-module PySide6 --exclude-module PyQt6 \
  --exclude-module PySide2 --exclude-module matplotlib --exclude-module numpy \
  --exclude-module pandas --exclude-module scipy --exclude-module tkinter \
  --exclude-module IPython --exclude-module jupyter --exclude-module notebook \
  entrypoint.py
```

## Project layout
```
darkweb-monitor/
  config/settings.py
  darkweb_monitor/
    crawler/   (tor_client, parsers, spider)
    ioc/       (extractor)
    ai/        (local, cloud, router, prompts)
    storage/   (models, db)
    alerts/    (notifier)
    scheduler/ (jobs)
    api/       (main, routes)
    pipeline.py
    cli.py
  dashboard/index.html
  data/
  tests/
```

## Tests
```bash
python -m pytest tests/ -q
```

## Governance & responsible use
This tool is for **authorized, defensive** monitoring only. Use isolated environments,
written authorization, passive collection, minimum necessary data, access controls.
Do not purchase stolen data, interact with illicit markets, or test third-party systems
without authorization. See SOC-DarkWatch governance for the full framework mapping.

## License
MIT