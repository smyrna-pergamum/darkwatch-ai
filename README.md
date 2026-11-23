<div align="center">

# DarkWatch AI

**Open-source, AI-powered darknet monitoring & threat intelligence platform** — self-hosted, defensive, local-first

<sub>repository: <code>darkwatch-ai</code> · Python package: <code>darkweb_monitor</code> · formerly "DarkWeb Monitor"</sub>

[![Release](https://img.shields.io/badge/release-v0.2.0-7c5cff)](https://github.com/smyrna-pergamum/darkwatch-ai/releases)
[![CI](https://github.com/smyrna-pergamum/darkwatch-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/smyrna-pergamum/darkwatch-ai/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-3776ab)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Status](https://img.shields.io/badge/status-developer%20preview-orange)

[Quick start](#quick-start) · [Features](#features) · [Threat intelligence](#threat-intelligence-darkwatch) · [AI & local models](#ai--local-models) · [AI analyst](#ai-analyst-agent) · [Learning](#learning-from-feedback) · [Configuration](#configuration) · [Changelog](CHANGELOG.md) · [🇹🇷 Türkçe kılavuz](docs/KULLANIM_TR.md)

<img src="docs/images/overview.png" alt="DarkWatch AI dashboard" width="900">

</div>

---

DarkWatch AI watches the places where an organisation's data tends to surface — Tor hidden
services, breach databases, leak and paste collections, ransomware leak sites — and tells you
when **your** domains, brands, e-mail addresses or other assets show up.

- **Collects** passively over a verified Tor connection, plus breach / leak / ransomware intelligence APIs.
- **Understands** pages with a local AI model: summaries, severity, entities, validated indicators.
- **Investigates** alerts with an AI analyst agent that uses tools, cites evidence and asks before acting.
- **Learns** from your corrections — without retraining the model and without trusting page content.
- **Profiles** threat actors, scores risk per organisation, preserves evidence with a verifiable chain of
  custody and hands confirmed findings to **IncidentForge** for incident response.
- **Runs on small local models** (GGUF via llama.cpp, Ollama, LM Studio, any OpenAI-compatible API):
  every input is chunked to fit the model's context window.

> [!IMPORTANT]
> For **authorised, defensive** monitoring of your own organisation only. The crawler never logs in,
> registers, posts, buys or downloads files. See [Responsible use](#responsible-use).

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Threat intelligence (DarkWatch)](#threat-intelligence-darkwatch)
- [Screenshots](#screenshots)
- [AI & local models](#ai--local-models)
- [AI analyst agent](#ai-analyst-agent)
- [Learning from feedback](#learning-from-feedback)
- [Configuration](#configuration)
- [CLI](#cli)
- [Architecture](#architecture)
- [Responsible use](#responsible-use)
- [Development & releases](#development--releases)
- [Roadmap](#roadmap)

## Quick start

### Option 1 — Release bundle (no Python needed)

1. Download `darkweb-monitor-0.2.0-<windows|linux|macos>-<arch>.zip` from
   [Releases](https://github.com/smyrna-pergamum/darkwatch-ai/releases) and extract it.
2. Start Tor (the `tor` service on port 9050, or Tor Browser on 9150 → set `TOR_PROXY_PORT=9150` in `.env`).
3. Double-click `DarkWebMonitor.exe` (Windows) or run `./DarkWebMonitor` (Linux/macOS) with no arguments.
   It creates the database, starts the dashboard on http://127.0.0.1:8000 and opens your browser.
   Keep the console window open while you use it; close it (or press Ctrl+C) to stop.
   The same executable is also the CLI, e.g. `DarkWebMonitor status` or `DarkWebMonitor serve --port 8080`.

   On macOS, if Gatekeeper blocks the unsigned app: `xattr -dr com.apple.quarantine darkweb-monitor-0.1.0`.
   On Windows, SmartScreen may warn about the unsigned exe: *More info → Run anyway*.

Configuration lives in the `.env` file next to the executable; data is stored in `data/` beside it.

### Option 2 — From source

```bash
git clone https://github.com/smyrna-pergamum/darkwatch-ai.git && cd darkwatch-ai
cp .env.example .env
pip install -r requirements.txt
python -m darkweb_monitor.cli init
python -m darkweb_monitor.cli serve            # http://127.0.0.1:8000
```

Then create your organization in the dashboard (*Organizations → + New organization*) or via the API:

```bash
curl -X POST http://127.0.0.1:8000/api/orgs -H "Content-Type: application/json" -d '{
  "name": "Example Corp", "sector": "finance",
  "assets": [{"asset_type": "domain", "value": "example.com"},
             {"asset_type": "brand", "value": "Example"}]}'
```

### Option 3 — Docker

```bash
export API_KEY=$(openssl rand -hex 24)
docker compose up -d                                   # monitor + Tor
docker compose --profile ai up -d                      # + Ollama
GGUF_FILE=qwen2.5-3b-instruct-q4_k_m.gguf \
  docker compose --profile llamacpp up -d              # + llama.cpp server (models in ./models)
```

### First steps in the dashboard

1. **Organizations** — create your company (tenant) and add its domains, brands, employee e-mails and
   executives. They become watch terms; alerts, risk score and exposure are tracked per organization.
   (The plain **Watchlist** still works for terms that belong to no tenant.)
2. **AI & Models** — connect a local model (LM Studio, Ollama, llama.cpp/GGUF …). Optional: without AI
   everything still works on rules.
3. **Targets** — add onion services you are authorised to monitor, choose a crawl mode and a schedule.
4. **Intel sources** — add API keys (HIBP, Intelligence X …) in `.env` to check breach and leak data.

## Features

| Area | What you get |
|---|---|
| **Collection** | Tor SOCKS5h crawler, GET-only · Tor exit verified before every run · NEWNYM circuit renewal · byte cap and content-type allow-list · `same_site` scope by default · abuse-content safety filter that discards pages unread |
| **Crawl modes** | **standard** (breadth-first) · **smart** (links ranked by relevance to your watchlist, optional AI re-scoring) · **agent** (an LLM chooses the next in-scope link toward a goal; every decision is logged) |
| **Intel sources** | Have I Been Pwned · Intelligence X · ransomware leak-site victims (ransomware.live) · Ahmia onion discovery |
| **Indicators** | Validated extraction (IPv4 with reserved/version filtering, Base58Check & Bech32 BTC, ETH, XMR, v3 onion, hashes, CVE, Telegram, Jabber, credentials with the password **masked**) · first/last seen · CISA KEV & Feodo correlation · enrichment via VirusTotal, AbuseIPDB, OTX, ThreatFox |
| **Alerts** | Deduplicated across runs and sources · new → acknowledged → resolved / false positive · AI triage · Discord, Slack, Teams, webhook, Telegram, e-mail · defanged URLs |
| **Automation** | Per-target interval or cron schedules · AI/rule planner proposes recrawls, new targets, watch terms and reviews · new targets always need a human |
| **AI analyst** | Tool-using agent with evidence-based reports and human approval for every state change → [details](#ai-analyst-agent) |
| **Learning** | Feedback → lessons, noise rules and regression tests → [details](#learning-from-feedback) |
| **Models** | Any OpenAI-compatible API, Ollama, Anthropic, built-in llama.cpp with a GGUF manager → [details](#ai--local-models) |
| **Sharing** | Export as CSV, JSON, **STIX 2.1**, **MISP**; push alerts to MISP |
| **Organizations** | Multi-tenant: assets (domain, brand, employee e-mail, executive, IP, wallet …) per organization · tenant-scoped API keys · shared collection, per-tenant alerts · exposure view (leaked employee credentials and e-mails, ransomware listings, actors) |
| **Threat intelligence** | Threat classification (12 classes, MITRE ATT&CK hints) · explainable 0–100 risk score per alert and per organization · threat-actor profiling from forum posts, contact handles and ransomware groups · entity relationship graph · onion page change diffs → [details](#threat-intelligence-darkwatch) |
| **Evidence** | SHA-256-addressed snapshots, hash-chained chain of custody, integrity verification, legal hold, ZIP bundle with manifest and `SHA256SUMS` |
| **IncidentForge** | One-click (or automatic) escalation of a finding with evidence, actors, indicators and risk into an IncidentForge case |
| **Governance** | Audit log · retention policy · API-key auth · no wildcard CORS · CSP & security headers · automatic, non-destructive schema upgrades |

## Threat intelligence (DarkWatch)

### Coverage

| Capability | How |
|---|---|
| Domain / company / brand monitoring | organization assets → watch terms (crawler, HIBP, IntelX, ransomware sites) |
| Employee e-mail monitoring | `employee_email` assets; domain assets match every address at the domain; HIBP domain search; exposure view |
| Credential leak detection | `email:password` combos (password masked and fingerprinted), HIBP, IntelX → `credential_leak` class |
| Ransomware victim monitoring | ransomware.live victims → `ransomware` alerts + ransomware-group actor |
| Darknet forum monitoring | forum parser (phpBB, XenForo, MyBB, vBulletin, SMF, Discourse, generic) → post authors and contacts |
| Onion website change detection | content hash + line diff (`change_summary`), watched terms in added text |
| IOC extraction | validated regex + AI extraction (hallucination-checked) |
| AI-powered threat classification | local-AI page category + keyword, source and IOC signals → threat class with confidence and signals |
| Threat actor profiling | actors, handles (forum, Telegram, Jabber, Tox, Session), venues, targets, activity, linked wallets, merge |
| Entity relationship graph | `/api/graph` over organizations, assets, alerts, sites, indicators, actors, handles |
| Risk scoring | explainable per-alert score; per-organization score with time decay |
| Evidence preservation | content-addressed snapshots + hash-chained custody log |
| Alerting | deduplicated alerts, triage, notifications (Discord, Slack, Teams, Telegram, e-mail, webhook) |
| REST API | `/api/...` (OpenAPI at `/docs`) |
| Multi-tenant organizations | organizations, asset links, tenant API keys scoped to `/api/orgs/{id}/…` |

### Risk scoring

Every alert gets a **0–100 risk score** with the factors that produced it: severity, threat-class weight
(ransomware and initial-access sales weigh most), the kind of asset matched, the AI triage verdict,
recurrence and whether a known threat actor is linked. An **organization's score** starts from its worst
open alert and adds the others with diminishing returns; each alert's weight halves every
`RISK_HALF_LIFE_DAYS` since it was last seen, and exposed employee credentials add to it.

### Evidence & chain of custody

Alerts at or above `EVIDENCE_AUTO_SEVERITY` are captured automatically (or press *Capture evidence*).
An item is a canonical JSON record — URL, title, masked page text, hashes, run, timestamps, collector —
stored gzip-compressed under `data/evidence/` and addressed by the SHA-256 of the uncompressed record.
Capture, verification, download, export, legal hold and escalation are appended to a custody log in
which every entry hashes the previous one. `POST /api/evidence/{id}/verify` re-hashes the file and walks
the chain, so a modified file or log entry is reported. Page retention does not delete evidence.

### Multi-tenant API

| Who | Key | Can reach |
|---|---|---|
| Admin | `API_KEY` from `.env` | everything |
| Tenant | `dwk_…` from *Organizations → + Tenant API key* (stored hashed, shown once) | `/api/orgs/{its id}` and its `/assets`, `/alerts`, `/risk`, `/exposure`, `/evidence` |

```bash
curl -H "X-API-Key: dwk_…" http://127.0.0.1:8000/api/orgs/1/exposure
```

Tenants can only register values nobody monitors yet (an administrator assigns shared or already-watched
domains, so a tenant cannot claim another company's assets and inherit its alerts), cannot add `regex` or
`keyword` assets, and see only their own matches on alerts shared with other organizations.

### IncidentForge integration

DarkWatch covers the *outside-in* view (what is leaked or offered about you); IncidentForge covers
incident response and forensics. *→ IncidentForge* on an alert (or `INCIDENTFORGE_AUTO_SEVERITY`) sends
one case with schema `darkwatch.incident/1`:

```
POST {INCIDENTFORGE_URL}{INCIDENTFORGE_INCIDENT_PATH}      Authorization: Bearer {INCIDENTFORGE_API_KEY}
{ "schema", "external_id", "title", "severity", "priority", "category", "risk_score", "risk_factors",
  "organizations", "matched_assets", "threat_actors", "indicators", "ai_triage",
  "evidence": [{ "sha256", "custody": [...], "content_b64" }], ... }
```

The returned `id` is stored on the alert (`incident_ref`), and an `escalated` entry is added to each
evidence item's custody log. `GET /api/alerts/{id}/incidentforge/preview` shows the payload without
evidence content.

## Screenshots

<sub>Shown with demo data.</sub>

<table>
<tr>
<td width="50%"><img src="docs/images/orgs.png" alt="Organizations"><br><sub><b>Organizations</b> — tenants with their risk score, assets and open alerts</sub></td>
<td width="50%"><img src="docs/images/actors.png" alt="Threat actors"><br><sub><b>Threat actors</b> — forum authors and ransomware groups, linked by shared contacts</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/images/graph.png" alt="Entity graph"><br><sub><b>Entity graph</b> — organizations, assets, alerts, sites, indicators and actors</sub></td>
<td width="50%"><img src="docs/images/evidence.png" alt="Evidence"><br><sub><b>Evidence</b> — SHA-256 snapshots with a verifiable chain of custody</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/images/analyst.png" alt="AI analyst"><br><sub><b>AI Analyst</b> — live transcript, tool calls, approvals and the final report</sub></td>
<td width="50%"><img src="docs/images/learning.png" alt="Learning"><br><sub><b>Learning</b> — AI agreement, lessons, noise rules and regression tests</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/images/ai-models.png" alt="AI & Models"><br><sub><b>AI & Models</b> — providers, privacy routing and local GGUF models</sub></td>
<td width="50%"><img src="docs/images/overview.png" alt="Overview"><br><sub><b>Overview</b> — open alerts, activity, organization risk, threat classes and actors</sub></td>
</tr>
</table>

## AI & local models

### Privacy routing

| Task | Sees | Runs on |
|---|---|---|
| Page analysis, link scoring, agent steps, AI analyst | raw dark-web text | **local providers only** (same machine / LAN), unless `CLOUD_ALLOW_RAW=true` |
| Run summaries, alert triage, task planning | locally produced summaries | remote first, local fallback — e-mails, IPs, wallets and passwords redacted (`CLOUD_REDACT`) |

Loopback and private-network addresses are classed as *local* automatically. Model output is treated as
untrusted: an indicator the model "finds" that does not appear in the page text is dropped.

### Connecting models

- **AI & Models → Add provider**: presets for LM Studio, Ollama, llama.cpp server, vLLM, LocalAI, Jan,
  OpenRouter, Groq, Together, Mistral, DeepSeek, OpenAI and Anthropic, or any OpenAI-compatible URL.
  *Load* lists the models, *Test* checks the connection.
- **GGUF models (llama.cpp)**: browse a Hugging Face repo (e.g. `Qwen/Qwen2.5-3B-Instruct-GGUF`) and download
  a file, download from any allowed https URL, upload from the browser, or register a file already on disk.
  `LLAMACPP_MODE` = `server` (your own `llama-server`) · `managed` (the app starts it with the active model) ·
  `embedded` (in-process via `llama-cpp-python`).

### Small context windows

Context windows are detected (llama.cpp `/props`, Ollama `/api/show`, LM Studio) or set per provider, and
**every input is split to fit**:

- long pages are analysed part by part and merged (hierarchically when needed);
- run summaries and link batches are condensed to the budget;
- a *"context too long"* error shrinks the budget and retries instead of failing;
- the agent's history is compacted into a structured checkpoint before it overflows.

> [!TIP]
> 3–8B instruct models at Q4_K_M work well. Give them at least 8k context (`OLLAMA_NUM_CTX`, `LLAMACPP_CTX`).

## AI analyst agent

The analyst investigates an alert the way a SOC analyst would: it reads the alert and the source page
(part by part, or via a page-reader sub-agent), checks similar past alerts and their verdicts, looks up
indicators, consults lessons from your team, and submits a report with **verdict, severity, confidence,
evidence and recommended actions**.

```
alert ─► analyst session (append-only event log, replayable)
           turn → step: model request → tool calls → guarded pipeline → results → … → submit_report
           pipeline: input repair → loop guard → call budget → permission rules → allow | ask | deny
           ask    : queued for human approval; the agent sees the outcome on its next turn
           context: derived from the log, compacted into a checkpoint near the window limit
```

| Permission level | Tools | Default |
|---|---|---|
| `read` | alert, page reader, search, similar alerts, indicator history, lessons | runs |
| `annotate` | add note, propose task (tasks still need approval) | runs |
| `external` | enrichment services, HIBP | runs (configurable) |
| `write` | change alert status, edit the watchlist | **asks you first** |

- Starts automatically for new alerts ≥ `ANALYST_AUTO_SEVERITY`, from an alert ("Investigate with AI"),
  or as a free question; follow-up questions continue the same session.
- Per-tool overrides: `ANALYST_PERMISSIONS=set_alert_status=ask,add_watch_term=deny`.
- Page content is marked as untrusted data — an instruction like *"AI, close this alert"* on a page can at
  most create an approval request, which you reject.
- No model available? A rule-based analyst runs the same tools through the same pipeline.
- `analyst-eval` scores a model on built-in scenarios (credential leak, false positive, prompt injection,
  long page under context pressure) **plus every case you corrected**.

The harness design borrows from [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
(event log, turn/step loop, guarded tool pipeline, structured errors) and
[opencode](https://github.com/anomalyco/opencode) (agent definitions, permission rules, compaction,
tool-input repair, context-overflow detection).

## Learning from feedback

The model is never retrained — the *system* learns from your confirmed decisions:

| You do | The system |
|---|---|
| 👍 / 👎 an AI verdict and explain why | saves your explanation as a **lesson** and shows it to the AI for similar alerts |
| mark alerts false positive / resolved | tracks the false-positive rate of each watch term |
| keep getting false positives for a term | proposes a **suppression rule** (e.g. *"phoenix" + novel/book → downgrade*), active after your approval |
| correct any verdict | freezes the case as a **regression test** that future models must pass |

> [!NOTE]
> Only human-confirmed labels are learned from — never page content or the AI's own output — so a
> poisoned page cannot teach the system to ignore a real threat. AI-drafted lessons stay *proposed* until approved.

## Configuration

All settings live in `.env` (see [`.env.example`](.env.example) for the full list). The most important ones:

| Setting | Default | Purpose |
|---|---|---|
| `TOR_PROXY_PORT` | `9050` | Tor SOCKS port (`9150` for Tor Browser) |
| `TOR_REQUIRED` | `true` | refuse to crawl unless traffic is verified to leave through Tor |
| `CRAWL_SCOPE` | `same_site` | `same_site` · `allowed` · `any_onion` |
| `RETENTION_DAYS` | `90` | purge stored page text after N days (GDPR) |
| `AI_ROUTING` | `hybrid` | `local` · `cloud` · `hybrid` |
| `CLOUD_ALLOW_RAW` | `false` | allow raw dark-web text to reach remote providers |
| `LOCAL_AI_BACKEND` | `ollama` | `ollama` · `llamacpp` |
| `LLAMACPP_MODE` | `server` | `server` · `managed` · `embedded` |
| `AI_DEFAULT_CONTEXT` | `4096` | assumed window when it cannot be detected |
| `ANALYST_AUTO_SEVERITY` | `high` | auto-investigate new alerts at or above this (`""` = off) |
| `ANALYST_ASK` | `write` | permission levels that wait for approval |
| `HIBP_API_KEY`, `INTELX_API_KEY` | — | breach and leak sources |
| `ALERT_WEBHOOK_URL`, `TELEGRAM_*`, `SMTP_*` | — | notifications |
| `API_KEY` | — | required when the server listens beyond localhost |
| `EVIDENCE_AUTO_SEVERITY` | `high` | capture evidence automatically for alerts at or above this (`""` = off) |
| `RISK_HALF_LIFE_DAYS` | `14` | an alert's weight in the organization score halves every N days |
| `ACTOR_PROFILING`, `FORUM_PARSING` | `true` | forum-author, contact and ransomware-group profiling |
| `INCIDENTFORGE_URL`, `INCIDENTFORGE_API_KEY` | — | IncidentForge escalation target |
| `INCIDENTFORGE_AUTO_SEVERITY` | — | open IncidentForge cases automatically at or above this |

## CLI

```text
init | status | serve | worker
crawl <url> [--mode standard|smart|agent] [--goal "..."] [--depth N] [--max-pages N]
target list | target add <url> [--mode agent --goal "..."] [--every 360 | --cron "0 */6 * * *"]
watch  list | watch add <kind> <value> [--severity high]
sources [hibp|intelx|ransomware|ahmia] · feeds · retention · newnym
analyst <alert_id> [--question "..."] [--provider rules|auto|db:ID]
analyst-eval [--provider auto] [--only credential_leak prompt_injection]
ai [--check]                       # providers and privacy routing
models list | download <url | REPO FILE> | register <path> | activate <id>
export --format stix|misp|csv|json [--out file]
```

Run with `python -m darkweb_monitor.cli …` (or the `DarkWebMonitor` executable). REST API docs:
`http://127.0.0.1:8000/docs` — send `X-API-Key` when `API_KEY` is set.

## Architecture

```
            ┌──────────── scheduler ────────────┐
            │ crawls · tasks · sources · feeds · analyst · learning · retention
            ▼
 RunManager ─► pipeline ─► Spider ─► TorClient (SOCKS5h, verified)
                  │          └─ frontier: BFS │ Smart │ Agent (LLM)
                  ├─ mask secrets · change detection · IOC extraction
                  ├─ watchlist ─► suppression rules ─► AIRouter (local ⇄ remote, chunking)
                  ├─ forum parser ─► threat actors (handles · sightings · profiles)
                  ├─ indicators (+ KEV / Feodo) ─► alerts (dedup · triage · notify · MISP)
                  │      └─ intel hook: classify · tenant link · risk · evidence · IncidentForge
                  └─ planner ─► tasks
 sources ─► HIBP · IntelX · ransomware.live · Ahmia ─► alerts
 analyst ─► harness (event log · tools · approvals · compaction) ─► reports ◄─ lessons
 organizations ─► assets ─► watch terms      evidence ─► custody chain ─► bundle / IncidentForge
 FastAPI (/api; tenants: /api/orgs/{id}) ─► dashboard (+ /ui/intel.js: orgs, actors, graph, evidence)
```

## Responsible use

Use DarkWatch AI only for **authorised, defensive** monitoring of your own organisation's assets,
from an isolated environment and with written approval.

- Keep `TOR_REQUIRED=true` and the default `same_site` scope unless you have a reason not to.
- Set a retention period that matches your data-protection obligations (e.g. GDPR / KVKK).
- Accessing or storing some dark-web content can be illegal — get legal advice for your jurisdiction.
- This is developer-preview software and has not had a security audit.

## Development & releases

```bash
pip install -r requirements-dev.txt
ruff check . && pytest -q
```

- Build a bundle for the current OS: `pip install pyinstaller && python packaging/build.py`
- Pushing a `v*` tag runs [`release.yml`](.github/workflows/release.yml): tests, builds Windows / Linux / macOS
  bundles and publishes a GitHub Release with notes from [`CHANGELOG.md`](CHANGELOG.md).

## Roadmap

Built along the lines of the internal *"Darkweb Monitoring Araştırması"* brief (multiple sources,
normalisation, provenance, STIX/MISP, GDPR-minded handling). Not yet included:
AI-written actor narratives · OpenCTI connector · TAXII 2.1 server · OpenSearch full-text index · Telegram and paste collectors ·
YARA / Sigma rule generation · Grafana / TheHive integration · LoRA fine-tuning from collected feedback.

## License

[MIT](LICENSE)
