import os
import sys

# isolate tests from any local .env / services
os.environ.update({
    "SCHEDULER_ENABLED": "false", "OLLAMA_ENABLED": "false", "TOR_ENABLED": "false",
    "TOR_REQUIRED": "false", "ALERT_CONSOLE": "false", "ALERT_FILE": "false",
    "ALERT_WEBHOOK_URL": "", "OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": "", "API_KEY": "",
    "CRAWL_DELAY_SEC": "0", "RANSOMWARE_LIVE_ENABLED": "false", "FEEDS_ENABLED": "false",
    "HIBP_API_KEY": "", "INTELX_API_KEY": "", "AHMIA_ENABLED": "false", "AI_TASK_PLANNER": "true",
    "AUTO_APPROVE_TASKS": "recrawl", "MISP_URL": "", "TELEGRAM_BOT_TOKEN": "", "SMTP_HOST": "", "INCIDENTFORGE_URL": "",
    "DWM_NO_RUNTIME": "1", "AI_AUTO_SETUP": "false", "TOR_MODE": "external",
})
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest  # noqa: E402

from darkweb_monitor.ai import router as router_mod  # noqa: E402
from darkweb_monitor.ai.base import AIError  # noqa: E402
from darkweb_monitor.crawler.tor_client import FetchResult  # noqa: E402
from darkweb_monitor.storage import db  # noqa: E402

ONION_A = "a" * 56 + ".onion"
ONION_B = "b" * 56 + ".onion"


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    from config.settings import settings
    monkeypatch.setattr(settings, "EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setattr(settings, "INCIDENTFORGE_URL", "")
    from config import runtime
    monkeypatch.setattr(runtime, "RUNTIME_FILE", tmp_path / "runtime.json")
    db.configure(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    db.init_db()
    router_mod.set_router(router_mod.AIRouter(local=Unavailable("ollama"), cloud=Unavailable("cloud")))
    yield
    router_mod.set_router(None)


class Unavailable:
    def __init__(self, name):
        self.name = name

    def available(self):
        return False

    def chat_json(self, *a, **k):
        raise AIError("unavailable")


class FakeProvider:
    """Scriptable AI provider: ``handler(prompt) -> dict``."""

    def __init__(self, name, handler, up=True, window=None):
        self.name, self.handler, self.up = name, handler, up
        self.context_window = window
        self.prompts = []

    def available(self):
        return self.up

    def chat_json(self, prompt, system=""):
        self.prompts.append(prompt)
        res = self.handler(prompt)
        if isinstance(res, Exception):
            raise res
        return res


class FakeClient:
    """Stands in for TorClient: serves pages from a dict."""

    def __init__(self, pages: dict[str, str]):
        self.pages = pages
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        if url not in self.pages:
            return FetchResult(url=url, final_url=url, status_code=404, error="HTTP 404")
        return FetchResult(url=url, final_url=url, status_code=200, content_type="text/html",
                           text=self.pages[url])


@pytest.fixture
def site():
    base = f"http://{ONION_A}"
    return {
        f"{base}/": f"""<html><title>Leak Forum</title><body>Welcome
            <a href="/thread/1">Database dump ACME corp</a>
            <a href="/thread/2">General chat</a>
            <a href="/login">Login</a>
            <a href="http://{ONION_B}/">partner market</a></body></html>""",
        f"{base}/thread/1": """<html><title>ACME dump</title><body>
            Selling acme-corp.com database. admin@acme-corp.com:hunter22 and
            contact 8.8.4.4, wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, CVE-2024-3400</body></html>""",
        f"{base}/thread/2": "<html><title>Chat</title><body>nothing to see here</body></html>",
        f"{base}/login": "<html><title>Login</title><body>login form</body></html>",
    }
