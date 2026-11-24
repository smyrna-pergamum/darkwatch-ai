"""Built-in help: how to use DarkWatch AI. Used by the assistant agent's
``app_help`` tool and by the help search when no AI model is available.
Keywords include Turkish terms so questions in either language match."""
from __future__ import annotations

import re

TOPICS: list[dict] = [
    {"id": "start", "title": "Getting started - the order of setup",
     "keywords": "start begin first setup order wizard checklist başla kurulum sıra ilk adım nasıl",
     "body": "Work through the setup checklist on the Overview page in order: 1) Connect to Tor (System → Tor → Connect). "
             "2) Local AI engine (AI & Models → Set up built-in AI; optional, rules are used meanwhile). "
             "3) Organizations: add your company and its domains, brands, employee e-mails and executives. "
             "4) Check the Watchlist. 5) Targets: add .onion sites you are authorised to monitor. 6) Run the first crawl. "
             "Scheduled crawls wait for Tor instead of failing and start automatically once Tor connects."},
    {"id": "tor", "title": "Tor connection, reconnect and new identity",
     "keywords": "tor connect bağlan bağlantı yenile reconnect proxy 9050 9150 onion bridge köprü snowflake obfs4 blocked engel verified circuit identity kimlik",
     "body": "System → Tor shows the connection. 'Connect' starts the built-in Tor: it downloads the official Tor Expert Bundle "
             "(verified with SHA-256) and connects. Bridge mode 'auto' tries a direct connection first and falls back to "
             "snowflake, obfs4 and meek bridges if the network blocks Tor (e.g. in Turkey). 'Reconnect' restarts Tor, "
             "'New identity' asks for fresh circuits, 'Re-check' verifies the exit via check.torproject.org, 'Stop' returns "
             "to the external Tor on TOR_PROXY_PORT (9050 daemon / 9150 Tor Browser). Custom bridges from "
             "bridges.torproject.org can be pasted with mode 'custom'. Crawls refuse to run until Tor is verified "
             "(TOR_REQUIRED=true) so your real IP is never exposed."},
    {"id": "ai", "title": "AI engine, models and providers",
     "keywords": "ai model yapay zeka llama llama.cpp gguf ollama provider sağlayıcı not found 404 download indir engine motor qwen local yerel",
     "body": "AI & Models → 'Set up built-in AI' downloads llama.cpp and a GGUF model (small 1.1 GB, balanced 2.1 GB, "
             "strong 4.7 GB) and runs it locally - nothing leaves the machine. In the packaged release this happens "
             "automatically when no local AI is found. Ollama is still supported: if OLLAMA_MODEL is not pulled the app "
             "uses the best installed Ollama model instead of failing with 'model not found'. More providers (LM Studio, "
             "vLLM, OpenRouter, any OpenAI-compatible URL) can be added; remote providers only receive masked summaries."},
    {"id": "orgs", "title": "Organizations (tenants) and assets",
     "keywords": "organization organisation kurum şirket tenant kiracı asset varlık domain alan adı brand marka employee çalışan email executive yönetici api key",
     "body": "Each organization is a tenant. Its domains, brands, employee e-mails and executives become watch terms. "
             "Collection is shared; each tenant only sees alerts its own assets matched, with its own risk score. "
             "'+ Tenant API key' creates a dwk_ key that only opens /api/orgs/{id}/... . Bulk-paste many e-mails at once."},
    {"id": "watchlist", "title": "Watchlist",
     "keywords": "watchlist watch term terim izleme listesi keyword anahtar kelime regex severity önem",
     "body": "The Watchlist holds the terms the crawler and the intel sources (HIBP, IntelX, ransomware) look for. "
             "Organization assets appear here automatically. Use general terms here only if they belong to no organization. "
             "If a term keeps producing false alarms, Learning proposes a suppression rule."},
    {"id": "targets", "title": "Targets and crawl modes",
     "keywords": "target hedef onion site crawl tarama standard smart agent schedule zamanlama cron depth derinlik",
     "body": "Targets are .onion services you are authorised to monitor. Modes: Standard (breadth-first), Smart (AI ranks "
             "links by relevance to your watchlist), Agent (AI navigates toward a goal and stops when reached). Each target "
             "can have a schedule ('every 6 hours', 'daily' or cron). New targets proposed by AI always wait for approval."},
    {"id": "alerts", "title": "Alerts, triage, risk score",
     "keywords": "alert alarm triage risk skor score severity false positive yanlış status durum acknowledge resolve",
     "body": "Alerts are deduplicated across runs and sources. Each has a threat class, a 0-100 risk score with its reasons, "
             "and an AI triage verdict. Open an alert to see matches, evidence and the analyst report; mark it acknowledged, "
             "resolved or false positive. 👍/👎 feedback teaches the system (Learning)."},
    {"id": "analyst", "title": "AI analyst and assistant",
     "keywords": "analyst analist assistant asistan yardım help investigate incele soru question chat agent ajan",
     "body": "Open an alert and press 'Investigate with AI', or ask a free question on the AI Analyst page. The analyst reads "
             "alerts, pages, similar cases and indicator history and writes a verdict with evidence. The assistant (the ? "
             "button) answers how-to questions about the app and suggests queries. Changing alert status or adding watch "
             "terms always waits for your approval."},
    {"id": "intel", "title": "Threat intelligence: actors, graph, changes",
     "keywords": "actor aktör threat tehdit forum graph grafik ilişki entity change değişiklik ioc indicator gösterge mitre",
     "body": "Forum posts are parsed; authors that mention your assets become threat actors with their contacts (Telegram, "
             "Jabber, Tox, Session). Ransomware groups are profiled too. Entity graph links organizations, assets, alerts, "
             "sites, indicators and actors. When an onion page changes, added and removed lines are stored."},
    {"id": "evidence", "title": "Evidence and chain of custody",
     "keywords": "evidence delil kanıt custody zincir hash export bundle zip legal hold verify doğrula",
     "body": "High-severity alerts are captured automatically (EVIDENCE_AUTO_SEVERITY); 'Capture evidence' does it by hand. "
             "Evidence is content-addressed (SHA-256) and every action is written to a hash-chained custody log. "
             "'Verify integrity' re-checks file and chain; 'Alert bundle (.zip)' exports manifest + SHA256SUMS."},
    {"id": "sources", "title": "Intel sources (HIBP, IntelX, ransomware)",
     "keywords": "source kaynak hibp have i been pwned intelx ransomware leak sızıntı api key anahtar",
     "body": "Put HIBP_API_KEY, INTELX_API_KEY or RANSOMWARE_LIVE_API_KEY into .env; the sources run on a schedule and "
             "match against the watchlist. Many APIs block Tor exits, so they go out directly unless EXTERNAL_API_VIA_TOR."},
    {"id": "incidentforge", "title": "IncidentForge integration",
     "keywords": "incidentforge incident olay case export entegrasyon",
     "body": "Set INCIDENTFORGE_URL and INCIDENTFORGE_API_KEY. '→ IncidentForge' on an alert sends one incident with class, "
             "risk, organizations, actors, IOCs and evidence. INCIDENTFORGE_AUTO_SEVERITY=critical escalates automatically."},
    {"id": "privacy", "title": "Privacy and safety",
     "keywords": "privacy gizlilik kvkk gdpr password parola retention saklama safety güvenlik ip",
     "body": "Raw dark-web content goes only to local models (CLOUD_ALLOW_RAW=false). Passwords from leaks are never stored. "
             "Page content older than RETENTION_DAYS is purged. The crawler is passive: no logins, no forms, no downloads."},
    {"id": "troubleshoot", "title": "Troubleshooting",
     "keywords": "error hata problem sorun çalışmıyor not working failed başarısız ssl eof timeout log",
     "body": "'Tor not verified ... SSLEOFError' means a Tor proxy answers but is not connected to the network - press Connect "
             "(built-in Tor with bridges). 'model not found' from Ollama: the app now switches to an installed model; or set "
             "up the built-in AI. Crawls stuck 'deferred' wait for Tor. Logs: data/tor/tor.log, data/llama-server.log and "
             "the Audit log under System."},
]
_WORD = re.compile(r"[\wçğıöşüÇĞİÖŞÜ.]+")


def _tokens(text: str) -> set[str]:
    return {w.lower() for w in _WORD.findall(text or "") if len(w) > 1}


def search(query: str, k: int = 3) -> list[dict]:
    q = _tokens(query)
    scored = []
    for t in TOPICS:
        kw, title = _tokens(t["keywords"]), _tokens(t["title"])
        body = _tokens(t["body"])
        s = 3 * len(q & kw) + 2 * len(q & title) + len(q & body)
        s += sum(1 for w in q for x in kw if len(w) > 3 and (x.startswith(w) or w.startswith(x)) and w != x)
        if s:
            scored.append((s, t))
    scored.sort(key=lambda x: -x[0])
    return [t for _, t in scored[:k]] or ([TOPICS[0]] if not q else [])


def get(topic_id: str) -> dict | None:
    return next((t for t in TOPICS if t["id"] == topic_id), None)
