# DarkWeb Monitor

**v0.1.0** · developer preview · [Changelog](CHANGELOG.md) · [Releases](https://github.com/smyrna-pergamum/darkweb-monitor/releases)

Self-hosted, **defensive** dark-web and leak monitoring for an organisation's own assets.
It crawls Tor hidden services you're authorised to monitor, queries breach, leak and
ransomware-leak-site intelligence, extracts and correlates indicators, and raises
deduplicated alerts. A hybrid AI layer adds **smart crawling**, an **agent crawler**,
an **AI analyst agent** that investigates alerts with tools, alert triage, run assessments and
**automatic follow-up tasks** — and it runs on small local models (GGUF via llama.cpp, Ollama,
LM Studio or any OpenAI-compatible API) thanks to context budgeting and chunking.

> Türkçe kısa kılavuz: [docs/KULLANIM_TR.md](docs/KULLANIM_TR.md)

## What it does

| Area | Features |
|---|---|
| **Collection** | Tor SOCKS5h crawler (GET only, no logins/forms), Tor exit verification before every run, circuit renewal (NEWNYM), byte cap and content-type allow-list, `same_site` scope by default, an abuse-content safety filter that throws pages away unread |
| **Crawl modes** | `standard` (breadth-first) · `smart` (best-first, links ranked by watchlist relevance with optional AI re-scoring) · `agent` (an LLM picks the next in-scope link step by step toward a goal, stops when the goal is met, and every decision is logged) |
| **Intel sources** | Have I Been Pwned (e-mails, verified domains) · Intelligence X (leaks, pastes, darknet) · ransomware leak-site victims (ransomware.live) · Ahmia onion search (suggests new targets) |
| **Processing** | Validated IOC extraction (IPv4 with reserved/version filtering, Base58Check/Bech32 BTC, ETH, XMR, v3 onion, hashes, CVE, Telegram, Jabber, e-mail:password with the password **masked**), page change detection, deduplicated indicators with first/last seen, CISA KEV and Feodo correlation |
| **Watchlist** | domain (matches subdomains and e-mails), brand, keyword, e-mail, IP, crypto, regex; severity per term |
| **Alerts** | Deduplicated across runs and sources, analyst workflow (new → acknowledged → resolved / false positive), AI triage, escalation on severity increase, Discord / Slack / Teams / generic webhook, Telegram, e-mail, file log; URLs/IOCs defanged |
| **Automation** | Per-target schedules (interval or cron), AI/rule planner proposes `recrawl`, `add_target`, `add_watch`, `review` tasks; low-risk kinds can be auto-approved, **new targets always need a human** |
| **Sharing** | Export indicators as CSV, JSON, **STIX 2.1** or **MISP** JSON; push alerts to MISP (manual or automatic by severity); enrichment via VirusTotal, AbuseIPDB, OTX, ThreatFox |
| **Governance** | Audit log, retention policy (page text purged after N days), API key auth, no wildcard CORS, CSP and security headers, additive schema migration from v1 |
| **AI analyst** | Tool-using agent (harness modelled on DeepSeek Harness / opencode): reads alerts, pages (chunked, or via a page-reader sub-agent), similar alerts, indicator history, enrichment and HIBP; writes a structured verdict with evidence. State-changing tools wait for human approval; prompt-injection resistant by design; evaluation harness included |
| **Models** | Provider registry: OpenAI-compatible APIs (LM Studio, Ollama, llama.cpp server, vLLM, LocalAI, Jan, OpenRouter, Groq, Together, Mistral, DeepSeek, OpenAI), Ollama native, Anthropic. llama.cpp backend (server / managed / embedded) with a GGUF manager: Hugging Face browser, URL download, upload, local path |
| **Small models** | Context window auto-detection, map-reduce chunking of long inputs, overflow recovery (shrink + retry), agent history compaction into checkpoints, tool input repair, output limits scaled to the window |
| **Learning** | Feedback on AI verdicts, lesson library retrieved into investigations, watch-term false-positive stats with proposed suppression rules, corrections frozen as regression tests |
| **UI** | Single-page dashboard: overview, alert queue with bulk actions, AI task inbox, targets with schedule/mode editor, live runs with agent timeline, sources, watchlist, pages, indicators, system |

## Privacy model for AI

| Task | Sees | Runs on |
|---|---|---|
| Page analysis, link scoring, agent steps | raw dark-web text / link anchors | **local model only** (Ollama) unless `CLOUD_ALLOW_RAW=true` |
| Run summary, alert triage, task planning | locally produced summaries and stats | cloud first (OpenAI/Anthropic), local fallback; e-mails/IPs/wallets/passwords redacted (`CLOUD_REDACT`) |

Without any AI, everything still works on rules: heuristic link ranking, rule-based run
summaries and planner. Model output is treated as untrusted: indicators the model
"finds" but which don't appear in the page text are dropped.

## AI analyst agent

```
alert ──► analyst session (append-only event log)
            turn/start → step: model request → tool calls → pipeline → tool results → … → submit_report
            pipeline: input repair → doom-loop guard → call budget → permission rules → allow | ask | deny
                      ask = approval request (human approves in the dashboard, the agent sees the outcome)
            context: derived from the log; compacted into a checkpoint when it nears the model window
```

* Starts automatically for new alerts ≥ `ANALYST_AUTO_SEVERITY`, from the alert drawer ("Investigate with AI")
  or as a free question; follow-up questions continue the same session.
* Permission levels: `read` and `annotate` (notes, *proposed* tasks) run directly, `external` (enrichment /
  HIBP) is configurable, `write` (alert status, watchlist) needs approval. Per-tool rules:
  `ANALYST_PERMISSIONS=set_alert_status=ask,add_watch_term=deny`.
* No model available? A rule-based analyst runs the same tools through the same pipeline.
* `python -m darkweb_monitor.cli analyst-eval --provider auto` scores your model on built-in scenarios
  (credential leak, false positive, prompt injection, long page under context pressure).

## Learning from feedback

The model is never retrained; the *system* learns from analysts:

| Feedback | Effect |
|---|---|
| 👍 / 👎 on an AI verdict, with the correct verdict and "why" | the explanation becomes a **lesson**; similar future alerts show it to the analyst agent, the triage and the rule-based analyst |
| alert marked false positive / resolved | implicit label for watch-term statistics |
| a watch term keeps producing false positives | a **suppression rule** is proposed (e.g. *"phoenix" + novel/book → downgrade*), applied after approval |
| any correction | frozen as a **regression case**; `analyst-eval` must keep passing it |

Only human-confirmed labels are used, so poisoned pages or the AI's own mistakes cannot teach the system.
Everything is managed on the **Learning** page.

## Local models and small context windows

1. **AI & Models → Add provider**: pick LM Studio / Ollama / llama.cpp server / vLLM / … or any
   OpenAI-compatible URL, press *Load* to list models and *Test*. Loopback/LAN addresses are trusted as
   *local* automatically.
2. **GGUF**: paste a Hugging Face repo (e.g. `Qwen/Qwen2.5-3B-Instruct-GGUF`), list its files and download one,
   or upload / register a file. With `LOCAL_AI_BACKEND=llamacpp` and `LLAMACPP_MODE=managed` the app starts
   `llama-server` with the active model for you.
3. Context windows are detected (llama.cpp `/props`, Ollama `/api/show`, LM Studio) or set per provider.
   Everything sent to a model is split to fit: long pages are analysed part by part and merged, run summaries
   are condensed hierarchically, link batches shrink, and a "context too long" error triggers a smaller retry
   instead of a failure. Tip: 3–8B instruct models at Q4_K_M work well; give them at least 8k context.

## Quick start

```bash
cp .env.example .env            # adjust Tor port, watch sources, AI, alerts
pip install -r requirements.txt
python -m darkweb_monitor.cli init
python -m darkweb_monitor.cli watch add domain example.com --severity high
python -m darkweb_monitor.cli serve           # http://127.0.0.1:8000
```

Tor: run the `tor` daemon (SOCKS 9050) or Tor Browser (SOCKS 9150, set `TOR_PROXY_PORT=9150`).
Local AI: install [Ollama](https://ollama.com) and `ollama pull qwen2.5:7b` (or set `OLLAMA_MODEL`).

### Release bundles (no Python needed)

Download `darkweb-monitor-0.1.0-<windows|linux|macos>-<arch>.zip` from the Releases page, extract it and run
`DarkWebMonitor init` then `DarkWebMonitor serve` (on Windows `DarkWebMonitor.exe`). Configuration lives in the
`.env` file next to the executable; data is stored in `data/` beside it.

### Docker

```bash
export API_KEY=$(openssl rand -hex 24)
docker compose up -d                     # monitor + Tor
docker compose --profile ai up -d        # + Ollama
GGUF_FILE=qwen2.5-3b-instruct-q4_k_m.gguf docker compose --profile llamacpp up -d   # + llama.cpp server (./models)
```

### CLI

```
init | status | serve | worker
crawl <url> [--mode standard|smart|agent] [--goal "..."] [--depth N] [--max-pages N]
crawl --target ID
target list | target add <url> [--mode agent --goal "..." --every 360 | --cron "0 */6 * * *"]
watch list | watch add <kind> <value> [--severity high]
sources [hibp|intelx|ransomware|ahmia]      feeds      retention      newnym
export --format stix|misp|csv|json [--out file]
analyst <alert_id> [--question "..."] [--provider rules|auto|db:ID]
analyst-eval [--provider auto] [--only credential_leak prompt_injection]
ai [--check]                                  # providers and routing
models list | models download <url | REPO FILE> | models register <path> | models activate <id>
```

API docs: `http://127.0.0.1:8000/docs` (send `X-API-Key` when `API_KEY` is set).

## Architecture

```
            ┌─────────── scheduler (APScheduler) ───────────┐
            │ per-target crawls · due tasks · sources · feeds · retention
            ▼
 RunManager (worker pool) ─► pipeline ─► Spider ─► TorClient (SOCKS5h, verified)
                                 │          └─ frontier: BFS | Smart | Agent(LLM)
                                 ├─ mask secrets ─ change detection ─ IOC extractor
                                 ├─ watchlist matcher ─ AIRouter (local ⇄ cloud, privacy classes)
                                 ├─ indicators + sightings (+ KEV / Feodo tags)
                                 ├─ alerts service (dedup, triage, notify, MISP)
                                 └─ planner → tasks (approve / auto-approve)
 sources runner ─► HIBP · IntelX · ransomware.live · Ahmia ─► alerts service
 FastAPI (/api, auth, exports) ─► dashboard/index.html
```

## How this lines up with the research brief

The design follows the "Darkweb Monitoring Araştırması" brief: data from more than Tor
alone (breach APIs, leak and ransomware sites, threat feeds), normalisation and
de-duplication, provenance (source, timestamps, confidence, verification status),
STIX 2.1 / MISP interoperability, and GDPR-minded handling (masking, retention, audit,
no logins). The following are **not** included yet and are good next steps:
OpenCTI connector, TAXII 2.1 server, OpenSearch full-text index, Telegram/paste collectors,
YARA/Sigma rule generation, and a Grafana/TheHive integration.

## Responsible use

Use this only for **authorised, defensive** monitoring of your own organisation's
assets, from an isolated environment, with written approval. The crawler is passive:
it never logs in, registers, posts, buys or downloads files. Keep the default
`same_site` scope unless you have a reason not to, keep `TOR_REQUIRED=true`, and set a
retention period that matches your data-protection obligations (e.g. GDPR).
Accessing or storing some dark-web content can be illegal, so get legal advice for
your jurisdiction.

## Development

```bash
pip install -r requirements-dev.txt
ruff check . && pytest -q
```

Release bundle for the current OS: `pip install pyinstaller && python packaging/build.py`.
Pushing a `v*` tag runs `.github/workflows/release.yml`, which tests, builds Windows / Linux / macOS bundles
and publishes a GitHub Release with notes from `CHANGELOG.md`.

MIT licensed.
