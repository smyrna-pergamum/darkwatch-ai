"""Central configuration via environment variables / .env."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("DWM_DATA_DIR", BASE_DIR / "data"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Tor / proxy ---------------------------------------------------------
    TOR_ENABLED: bool = True
    # Refuse to crawl when Tor is not reachable / not verified. Disabling this
    # can expose your real IP address - only do so in a lab.
    TOR_REQUIRED: bool = True
    TOR_PROXY_HOST: str = "127.0.0.1"
    TOR_PROXY_PORT: int = 9050  # 9150 for Tor Browser
    TOR_CONTROL_PORT: int = 9051
    TOR_CONTROL_PASSWORD: str = ""
    TOR_NEWNYM_EVERY_RUN: bool = False  # request a fresh circuit before each run
    TOR_CHECK_URL: str = "https://check.torproject.org/api/ip"
    # external: use the Tor you run (TOR_PROXY_PORT); managed: the app downloads and starts its own Tor
    TOR_MODE: str = "external"
    TOR_BIN: str = ""                       # tor executable for managed mode ("" = download / data/tor)
    TOR_MANAGED_SOCKS_PORT: int = 9060
    TOR_MANAGED_CONTROL_PORT: int = 9061
    # direct | auto (direct, then bridges if blocked) | snowflake | obfs4 | meek | webtunnel | custom
    TOR_BRIDGE_MODE: str = "auto"
    TOR_BRIDGES: str = ""                   # custom bridge lines, separated by newlines or "|"
    TOR_DIST_URL: str = "https://dist.torproject.org/torbrowser/"
    REQUEST_TIMEOUT: int = 45
    MAX_RETRIES: int = 2
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

    # --- Crawler -------------------------------------------------------------
    CRAWL_DEPTH: int = 2
    CRAWL_MAX_PAGES: int = 50
    CRAWL_DELAY_SEC: float = 2.0
    # same_site: stay on the start host (default, safest)
    # allowed:   same host + hosts listed in ALLOWED_DOMAINS
    # any_onion: follow any .onion link (broad discovery - use with care)
    CRAWL_SCOPE: str = "same_site"
    ALLOWED_DOMAINS: str = ""  # comma-separated host suffixes
    MAX_RESPONSE_BYTES: int = 2_000_000
    ALLOWED_CONTENT_TYPES: str = "text/html,text/plain,application/xhtml+xml"
    CRAWL_CONCURRENCY: int = 1  # parallel runs (Tor is slow; keep low)
    # Pages containing any of these terms are discarded immediately, never
    # stored or sent to AI, and the host is blocked for the rest of the run.
    SAFETY_BLOCK_TERMS: str = "child porn,childporn,cp links,pthc,jailbait,underage sex,preteen"

    # --- Storage -------------------------------------------------------------
    DATABASE_URL: str = f"sqlite:///{(DATA_DIR / 'monitor.db').as_posix()}"
    STORE_PAGE_CONTENT: bool = True
    MAX_STORED_CONTENT_CHARS: int = 20000
    RETENTION_DAYS: int = 90  # page content older than this is purged (0 = keep)

    # --- AI (hybrid) ---------------------------------------------------------
    OLLAMA_ENABLED: bool = True
    OLLAMA_BASE_URL: str = "http://127.0.0.1:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    OLLAMA_TIMEOUT: int = 180
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-5-haiku-latest"
    AI_CLOUD_PROVIDER: str = "openai"  # openai | anthropic
    # local | cloud | hybrid
    #   hybrid: raw dark-web content -> local only; derived data -> cloud first
    AI_ROUTING: str = "hybrid"
    # Allow raw page content to be sent to a cloud provider. Off by default.
    CLOUD_ALLOW_RAW: bool = False
    # Mask emails / IPs / crypto addresses in anything sent to the cloud.
    CLOUD_REDACT: bool = True
    AI_PAGE_MAX_CHARS: int = 40000      # cap per page; longer pages are sampled
    # Context budgeting - inputs larger than a model's window are split into
    # chunks (map) and merged (reduce) instead of failing with "context too long".
    AI_DEFAULT_CONTEXT: int = 4096      # assumed window for local models when unknown
    AI_REMOTE_CONTEXT: int = 32000      # assumed window for remote APIs when unknown
    AI_RESERVE_OUTPUT_TOKENS: int = 1024
    AI_MAX_CHUNKS: int = 24
    OLLAMA_NUM_CTX: int = 8192          # sent to Ollama as options.num_ctx

    # --- Local AI backend -----------------------------------------------------
    LOCAL_AI_BACKEND: str = "ollama"  # ollama | llamacpp
    # llama.cpp:
    #   server   - connect to a llama-server you run yourself (OpenAI-compatible API)
    #   managed  - the app starts llama-server with the active GGUF model
    #   embedded - load the GGUF in-process via llama-cpp-python (optional dependency)
    LLAMACPP_MODE: str = "server"
    LLAMACPP_BASE_URL: str = "http://127.0.0.1:8080"
    LLAMACPP_API_KEY: str = ""
    LLAMACPP_SERVER_BIN: str = "llama-server"  # path to the llama.cpp server binary (managed mode)
    LLAMACPP_PORT: int = 8089                  # port used in managed mode
    LLAMACPP_CTX: int = 8192
    LLAMACPP_GPU_LAYERS: int = 0               # -ngl; 0 = CPU only, 99 = everything on GPU
    LLAMACPP_THREADS: int = 0                  # 0 = llama.cpp default
    LLAMACPP_EXTRA_ARGS: str = ""
    LLAMACPP_TIMEOUT: int = 300
    MODELS_DIR: str = str(DATA_DIR / "models")
    MODEL_MAX_UPLOAD_GB: float = 60.0
    # hosts GGUF downloads may come from ("" = any https host)
    MODEL_DOWNLOAD_HOSTS: str = "huggingface.co,hf.co,cdn-lfs.huggingface.co,cdn-lfs.hf.co,cdn-lfs-us-1.hf.co,cas-bridge.xethub.hf.co,xethub.hf.co,modelscope.cn,github.com,objects.githubusercontent.com"
    HF_TOKEN: str = ""  # Hugging Face token for gated / private GGUF repos
    HF_ENDPOINT: str = "https://huggingface.co"
    # Built-in AI engine: download llama.cpp + a GGUF model and run it locally.
    # auto = only in the packaged release when no local AI is available; true / false
    AI_AUTO_SETUP: str = "auto"
    AI_DEFAULT_MODEL: str = "balanced"         # small | balanced | strong (see ai/engine.py)
    LLAMACPP_RELEASES_API: str = "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=15"

    # --- Analyst agent (harness) ---------------------------------------------
    ANALYST_ENABLED: bool = True
    ANALYST_PROVIDER: str = "auto"  # auto | llamacpp | ollama | openai | anthropic | rules
    ANALYST_MODEL: str = ""          # override model name for the analyst
    ANALYST_MAX_STEPS: int = 12
    ANALYST_MAX_TOOL_CALLS: int = 30
    ANALYST_MAX_CONTEXT_CHARS: int = 60000
    ANALYST_TOOL_RESULT_CHARS: int = 6000
    # permission levels run without asking; others create an approval request
    ANALYST_AUTO_APPROVE: str = "read,annotate,external"
    ANALYST_ASK: str = "write"
    # opencode-style per-tool rules, last match wins, e.g. "set_alert_status=ask,add_watch_term=deny"
    ANALYST_PERMISSIONS: str = ""
    ANALYST_AUTO_SEVERITY: str = "high"  # auto-investigate new alerts >= this ("" = off)
    ANALYST_AUTO_MAX_PER_HOUR: int = 6

    # --- Smart / agent crawling ---------------------------------------------
    AGENT_MAX_STEPS: int = 25
    AGENT_CANDIDATES: int = 15  # links shown to the agent per step
    SMART_SCORE_BATCH: int = 40  # links scored per AI call in smart mode

    # --- Automatic tasks -----------------------------------------------------
    AI_TASK_PLANNER: bool = True
    # Low-risk tasks the planner may approve by itself (recrawl, review).
    # New targets / watch terms always need human approval.
    AUTO_APPROVE_TASKS: str = "recrawl"

    # --- Alerts --------------------------------------------------------------
    ALERT_MIN_SEVERITY: str = "medium"  # low | medium | high | critical
    ALERT_CONSOLE: bool = True
    ALERT_FILE: bool = True
    ALERT_FILE_PATH: str = str(DATA_DIR / "alerts.log")
    ALERT_WEBHOOK_URL: str = ""  # Discord / Slack / Teams / generic JSON
    ALERT_WEBHOOK_FORMAT: str = "auto"  # auto | discord | slack | teams | generic
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_TO: str = ""  # comma-separated
    AI_TRIAGE: bool = True
    # Do not send notifications for alerts the AI triage marks as false
    # positives (the alert is still stored and visible in the dashboard).
    AI_TRIAGE_SUPPRESS: bool = False

    # --- External intelligence sources --------------------------------------
    # Breach / leak APIs complement the crawler: most leak data never sits on
    # a crawlable .onion page. All sources are optional (enabled when keyed).
    SOURCES_INTERVAL_MIN: int = 720
    EXTERNAL_API_VIA_TOR: bool = False  # many APIs (e.g. HIBP) block Tor exits
    HIBP_API_KEY: str = ""
    HIBP_CHECK_DOMAINS: bool = True  # domain search needs a verified domain in HIBP
    INTELX_API_KEY: str = ""
    INTELX_BASE_URL: str = "https://2.intelx.io"  # free tier: https://free.intelx.io
    INTELX_MAX_RESULTS: int = 20
    RANSOMWARE_LIVE_ENABLED: bool = True  # public victim list of ransomware leak sites
    RANSOMWARE_LIVE_URL: str = "https://api.ransomware.live/v2"
    RANSOMWARE_LIVE_API_KEY: str = ""
    AHMIA_ENABLED: bool = True  # onion search for watch terms -> target suggestions
    AHMIA_URL: str = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
    AHMIA_CLEARNET_URL: str = "https://ahmia.fi"
    # tor: only through Tor | auto: Tor, then the clearnet mirror if Tor is down | clearnet: always ahmia.fi
    AHMIA_MODE: str = "auto"
    AHMIA_MAX_RESULTS: int = 30
    # More onion search engines (OnionSearch-style), one per line: name|url-with-{q}
    ONION_SEARCH_ENABLED: bool = False
    ONION_SEARCH_ENGINES: str = (
        "torch|http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query={q}\n"
        "haystak|http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={q}\n"
        "tor66|http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={q}\n"
        "excavator|http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={q}\n"
        "onionland|http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={q}")
    # Infostealer intelligence (free, no key): Hudson Rock Cavalier OSINT API
    HUDSONROCK_ENABLED: bool = True
    HUDSONROCK_URL: str = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
    # Certificate transparency (free): new certificates with your brand / domain -> phishing look-alikes
    CRTSH_ENABLED: bool = True
    CRTSH_MAX_RESULTS: int = 200
    # Paste-site dumps (free): psbdmp.ws pastebin dump search
    PSBDMP_ENABLED: bool = False
    # Keyed breach / leak / exposure APIs
    LEAKCHECK_API_KEY: str = ""       # leakcheck.io (v2)
    DEHASHED_API_KEY: str = ""        # dehashed.com (v2 API key)
    LEAKIX_API_KEY: str = ""          # leakix.net - exposed services & leaks
    GITHUB_SEARCH_TOKEN: str = ""            # GitHub code search for leaked secrets mentioning your domains
    URLSCAN_API_KEY: str = ""         # urlscan.io - phishing pages using your brand / domain
    SHODAN_API_KEY: str = ""          # Shodan - internet-exposed hosts of your domains
    GREYNOISE_API_KEY: str = ""       # enrichment: is an IP a scanner / benign service

    # --- Threat feeds & enrichment -------------------------------------------
    FEEDS_ENABLED: bool = True
    FEEDS_INTERVAL_HOURS: int = 24
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    FEODO_URL: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    ABUSECH_AUTH_KEY: str = ""  # ThreatFox / URLhaus lookups
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # --- MISP export ---------------------------------------------------------
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True
    MISP_AUTO_PUSH_SEVERITY: str = ""  # e.g. "high" -> push alerts >= high automatically

    # --- DarkWatch AI: evidence, risk, actors, IncidentForge ------------------
    EVIDENCE_ENABLED: bool = True
    EVIDENCE_DIR: str = ""  # default: <data>/evidence
    EVIDENCE_AUTO_SEVERITY: str = "high"  # capture evidence automatically for alerts >= this ("" = off)
    RISK_HALF_LIFE_DAYS: float = 14.0  # alert contribution to org risk halves every N days
    RISK_WINDOW_DAYS: int = 90
    ACTOR_PROFILING: bool = True  # extract forum authors / contacts / ransomware groups as actors
    FORUM_PARSING: bool = True
    INCIDENTFORGE_URL: str = ""  # e.g. https://incidentforge.local
    INCIDENTFORGE_API_KEY: str = ""
    INCIDENTFORGE_INCIDENT_PATH: str = "/api/v1/incidents"
    INCIDENTFORGE_VERIFY_TLS: bool = True
    INCIDENTFORGE_AUTO_SEVERITY: str = ""  # e.g. "critical" -> open incidents automatically
    INCIDENTFORGE_INCLUDE_EVIDENCE: bool = True  # attach evidence content (base64) to the case

    # --- Scheduler -----------------------------------------------------------
    SCHEDULER_ENABLED: bool = True
    DEFAULT_INTERVAL_MIN: int = 360

    # --- API -----------------------------------------------------------------
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    API_KEY: str = ""  # required when API_HOST is not loopback
    CORS_ORIGINS: str = ""  # comma-separated; empty = same-origin only

    def list_of(self, name: str) -> list[str]:
        return [x.strip() for x in str(getattr(self, name, "")).split(",") if x.strip()]


settings = Settings()

# Resolve relative sqlite paths against BASE_DIR (important for frozen exe)
_db = settings.DATABASE_URL
if _db.startswith("sqlite:///") and not _db.startswith("sqlite:////"):
    _rel = _db[len("sqlite:///"):]
    if not os.path.isabs(_rel) and not (len(_rel) > 1 and _rel[1] == ":"):
        settings.DATABASE_URL = f"sqlite:///{(BASE_DIR / _rel).as_posix()}"

if not os.environ.get("DWM_NO_RUNTIME"):  # tests start from .env only
    from .runtime import load as _load_runtime
    _load_runtime()
    from .intel_store import load as _load_intel
    _load_intel()


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if settings.DATABASE_URL.startswith("sqlite:///"):
        Path(settings.DATABASE_URL[len("sqlite:///"):]).parent.mkdir(parents=True, exist_ok=True)
