# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/) (0.x = developer preview: breaking
changes possible between minor versions).

## [0.1.0] - 2026-11-23

First tagged release: a full rewrite of the initial prototype.

### Security & privacy
- Raw dark-web text is only sent to **local** AI providers (same machine / LAN); remote providers receive redacted, derived data unless `CLOUD_ALLOW_RAW=true`.
- Tor exit is verified before every crawl (`TOR_REQUIRED`); NEWNYM circuit renewal.
- Passive GET-only crawler, `same_site` scope by default, byte cap, content-type allow-list and an abuse-content safety filter that discards pages unread.
- API key auth (required for non-loopback binds), no wildcard CORS, CSP and security headers.
- Credentials found in leaks are masked before storage; passwords are never stored.
- Audit log, retention policy for page content, additive migration from the prototype schema.

### Collection & processing
- Crawl modes: **standard** (BFS), **smart** (relevance-ranked frontier with AI re-scoring), **agent** (LLM-steered, every decision logged).
- Validated IOC extraction (Base58Check/Bech32 BTC, ETH, XMR, v3 onion, CVE, Telegram, Jabber, credentials), deduplicated indicators with first/last seen, change detection.
- Watchlist (domain, brand, keyword, e-mail, IP, crypto, regex) with per-term severity.
- Intel sources: Have I Been Pwned, Intelligence X, ransomware leak-site victims (ransomware.live), Ahmia onion discovery.
- Threat feeds (CISA KEV, Feodo Tracker) and enrichment (VirusTotal, AbuseIPDB, OTX, ThreatFox).
- Deduplicated alerts with analyst workflow, AI triage and escalation; Discord / Slack / Teams / webhook / Telegram / e-mail notifications.
- AI/rule task planner with an approval inbox; per-target interval or cron schedules.
- Exports: CSV, JSON, STIX 2.1, MISP; MISP push.

### AI agent harness & analyst
- Agent harness modelled on DeepSeek Harness and opencode: append-only session event log ("model-visible means logged"), turn/step loop, tool registry with a guarded execution pipeline (input repair → policy → approval → timeout → retention), waterfall hooks, structured error codes, doom-loop guard, opencode-style permission rules.
- **AI Analyst** agent: investigates alerts with 15 tools (alert, page reader, page-reader sub-agent, search, similar alerts, indicator history, enrichment, HIBP, notes, task proposals, status changes, watchlist edits) and submits a structured report (verdict, severity, confidence, evidence, actions). State-changing actions wait for human approval. Auto-investigation of new high-severity alerts; rule-based fallback when no model is available.
- Evaluation harness (`analyst-eval`) with credential-leak, false-positive, prompt-injection and long-page scenarios.

### Learning from analyst feedback (no model retraining)
- 👍/👎 feedback on every AI verdict (alert drawer and analyst report) with the correct verdict and an explanation; alert status changes are recorded as implicit labels; AI agreement rate per provider.
- **Lesson library**: human explanations become lessons that are retrieved (offline BM25-style + watch-term matching) into future investigations, triage and the rule-based analyst; lessons get credit/blame from later feedback. AI-drafted lessons stay *proposed* until approved.
- **Watch-term quality**: true/false-positive rates per watch term; for noisy terms the system proposes context **suppression rules** (words that occur around false positives but never around true positives) - downgrade or suppress, active only after approval.
- **Regression cases**: every correction is frozen (masked) as an evaluation scenario; `analyst-eval` runs them with the current lessons, from the CLI or the dashboard.
- Safety: only human-confirmed labels are learned from - never page content or the AI's own output.

### Models & small-model support
- Provider registry: any **OpenAI-compatible** API (LM Studio, Ollama, llama.cpp server, vLLM, LocalAI, Jan, OpenRouter, Groq, Together, Mistral, DeepSeek, OpenAI) plus Ollama native and Anthropic; connection test and model listing in the dashboard.
- **llama.cpp** backend in three modes (external server, managed `llama-server`, embedded `llama-cpp-python`) and a **GGUF model manager**: Hugging Face repo browser and download (with `HF_TOKEN`), any https URL, browser upload with progress, local path registration, GGUF header validation and metadata.
- **Context budgeting** for small models: context windows auto-detected (llama.cpp `/props`, Ollama `/api/show`, LM Studio) or configured; inputs split into chunks that fit (map) and merged hierarchically (reduce); "context too long" errors shrink the budget and retry; agent history compaction into structured checkpoints; tool output and page parts scaled to the window.

### UI
- New single-page dashboard: overview, alerts, AI analyst (live transcript, tool cards, approvals, report), AI tasks, targets, runs (agent timeline), intel sources, watchlist, pages, indicators, AI & Models, system.

### Packaging
- Docker image and compose (Tor, optional Ollama / llama.cpp server), GitHub Actions CI, release workflow building Windows / Linux / macOS bundles with PyInstaller.
