"""Start-up order and readiness gating, built-in Tor, built-in AI engine,
Ollama model fallback, text tool-call parsing, assistant and suggestions."""
import io
import json
import tarfile
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from config import runtime
from config.settings import settings
from darkweb_monitor import readiness, tor_manager
from darkweb_monitor.ai import engine
from darkweb_monitor.api.main import app


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------ runtime settings
def test_runtime_settings_roundtrip(monkeypatch):
    monkeypatch.setattr(settings, "LOCAL_AI_BACKEND", "ollama")
    runtime.save(LOCAL_AI_BACKEND="llamacpp")
    assert settings.LOCAL_AI_BACKEND == "llamacpp"
    assert json.loads(runtime.RUNTIME_FILE.read_text())["LOCAL_AI_BACKEND"] == "llamacpp"
    monkeypatch.setattr(settings, "LOCAL_AI_BACKEND", "ollama")
    assert runtime.load() == {"LOCAL_AI_BACKEND": "llamacpp"} and settings.LOCAL_AI_BACKEND == "llamacpp"
    with pytest.raises(ValueError):
        runtime.save(API_KEY="steal")  # secrets / arbitrary keys are not writable


# ------------------------------------------------------------------ Ollama: missing model
def test_ollama_missing_model_falls_back_to_installed_one(monkeypatch):
    from darkweb_monitor.ai.local import OllamaClient, pick_model
    assert pick_model(["nomic-embed-text", "qwen2.5-coder:3b", "qwen3:8b"]) == "qwen3:8b"
    assert pick_model(["nomic-embed-text"]) is None
    c = OllamaClient(model="qwen2.5:7b")
    monkeypatch.setattr(settings, "OLLAMA_MODEL", "qwen2.5:7b")
    assert c._resolve_model(["qwen3:8b", "qwen2.5-coder:3b"]) is True
    assert c.model == "qwen3:8b" and c.substituted == ("qwen2.5:7b", "qwen3:8b")
    c2 = OllamaClient(model="llama3")
    assert c2._resolve_model(["llama3:latest"]) and c2.model == "llama3"
    assert OllamaClient(model="x")._resolve_model([]) is False


def test_tool_calls_printed_as_bare_json_are_parsed():
    from darkweb_monitor.harness.llm import _calls_in_text
    calls = _calls_in_text('{"name": "app_help", "arguments": {"question": "tor"}}\n{"name": "app_status", "arguments": {}}')
    assert [c["name"] for c in calls] == ["app_help", "app_status"] and calls[0]["args"] == {"question": "tor"}
    assert _calls_in_text('```json\n{"name": "search", "parameters": {"query": "x"}}\n```')[0]["name"] == "search"
    assert _calls_in_text('{"verdict": "ok"}') == [] and _calls_in_text("plain answer") == []


# ------------------------------------------------------------------ built-in Tor
PT = {"recommendedDefault": "obfs4",
      "pluggableTransports": {"lyrebird": "ClientTransportPlugin meek_lite,obfs4,webtunnel exec ${pt_path}lyrebird.exe",
                              "snowflake": "ClientTransportPlugin snowflake exec ${pt_path}lyrebird.exe"},
      "bridges": {"snowflake": ["snowflake 192.0.2.3:80 2B28 fingerprint=2B28 url=https://x.example/"],
                  "obfs4": ["obfs4 1.2.3.4:443 ABCD cert=xyz iat-mode=0"]}}


@pytest.fixture
def fake_tor(tmp_path, monkeypatch):
    monkeypatch.setattr(tor_manager, "TOR_DIR", tmp_path / "tor")
    bin_dir = tmp_path / "tor" / "tor"
    (bin_dir / "pluggable_transports").mkdir(parents=True)
    (bin_dir / "pluggable_transports" / "pt_config.json").write_text(json.dumps(PT))
    exe = bin_dir / tor_manager._exe("tor")
    exe.write_text("")
    monkeypatch.setattr(settings, "TOR_BIN", "")
    yield str(exe)
    tor_manager.stop(persist=False)


def test_torrc_with_bridges(fake_tor):
    torrc = tor_manager.write_torrc(fake_tor, "snowflake", 9060, 9061).read_text()
    assert "SocksPort 127.0.0.1:9060" in torrc and "ControlPort 127.0.0.1:9061" in torrc
    assert "UseBridges 1" in torrc and "Bridge snowflake 192.0.2.3:80" in torrc
    assert "${pt_path}" not in torrc and "pluggable_transports" in torrc
    assert "UseBridges" not in tor_manager.write_torrc(fake_tor, "direct", 9060, 9061).read_text()
    with pytest.raises(tor_manager.TorSetupError):
        tor_manager.bridge_lines(fake_tor, "custom")  # nothing pasted yet


def test_custom_bridge_lines_are_validated(monkeypatch):
    monkeypatch.setattr(settings, "TOR_BRIDGES", "Bridge obfs4 1.2.3.4:443 FP cert=a+b/c= iat-mode=0\n# comment\nrm -rf /; $(x)")
    assert tor_manager.custom_bridges() == ["obfs4 1.2.3.4:443 FP cert=a+b/c= iat-mode=0"]


def test_latest_bundle_picks_newest_stable_with_checksum(monkeypatch):
    monkeypatch.setattr(tor_manager, "_platform_tag", lambda: "windows-x86_64")
    pages = {"https://dist.torproject.org/torbrowser/": '<a href="15.0.9/">x</a><a href="16.0.2/">x</a><a href="16.0a1/">a</a>',
             "https://dist.torproject.org/torbrowser/16.0.2/sha256sums-signed-build.txt": "aa  tor-expert-bundle-android-x86_64-16.0.2.tar.gz",
             "https://dist.torproject.org/torbrowser/15.0.9/sha256sums-signed-build.txt":
                 "ABC123  tor-expert-bundle-windows-x86_64-15.0.9.tar.gz"}

    class R:
        def __init__(self, t):
            self.text, self.status_code = t, 200 if t is not None else 404

    class C:
        def get(self, url):
            return R(pages.get(url))
    v, url, sha = tor_manager.latest_bundle(C())
    assert v == "15.0.9" and url.endswith("/15.0.9/tor-expert-bundle-windows-x86_64-15.0.9.tar.gz") and sha == "abc123"


def test_tar_with_path_traversal_is_rejected(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("../../evil.txt")
        info.size = 1
        t.addfile(info, io.BytesIO(b"x"))
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r:gz") as t, pytest.raises(tor_manager.TorSetupError):
        tor_manager._safe_extract(t, tmp_path / "out")


def test_auto_mode_falls_back_to_bridges_and_sets_proxy(fake_tor, monkeypatch):
    tried = []

    def fake_try(tor_bin, transport):
        tried.append(transport)
        tor_manager.state.update(socks_port=9062, control_port=9063, error=None if transport == "snowflake" else "stuck")
        return transport == "snowflake"
    monkeypatch.setattr(tor_manager, "_try", fake_try)
    monkeypatch.setattr(tor_manager, "_kill", lambda: None)
    tor_manager.start("auto")
    for _ in range(100):
        if tor_manager.state["status"] in ("connected", "failed"):
            break
        time.sleep(0.05)
    assert tried == ["direct", "snowflake"] and tor_manager.state["status"] == "connected"
    assert settings.TOR_PROXY_PORT == 9062 and settings.TOR_MODE == "managed"
    tor_manager.stop()
    assert settings.TOR_PROXY_PORT == tor_manager._EXTERNAL[0] and settings.TOR_MODE == "external"


# ------------------------------------------------------------------ built-in AI engine
def test_pick_release_skips_releases_without_a_build(monkeypatch):
    monkeypatch.setattr(engine, "asset_patterns", lambda: ["-bin-win-cpu-x64.zip"])
    rels = [{"tag_name": "v1.0.0", "assets": [{"name": "nightly-tag.txt"}]},
            {"tag_name": "b12655", "assets": [{"name": "llama-b12655-bin-win-vulkan-x64.zip"},
                                              {"name": "llama-b12655-bin-win-cpu-x64.zip", "size": 1}]}]
    tag, asset = engine.pick_release(rels)
    assert tag == "b12655" and asset["name"] == "llama-b12655-bin-win-cpu-x64.zip"
    with pytest.raises(engine.EngineError):
        engine.pick_release(rels[:1])


def test_engine_zip_traversal_rejected(tmp_path):
    p = tmp_path / "x.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("../evil.dll", "x")
    with pytest.raises(engine.EngineError):
        engine._extract(p, tmp_path / "out")


def test_engine_setup_flow_switches_to_builtin(monkeypatch):
    from darkweb_monitor.ai import llamacpp, models
    monkeypatch.setattr(engine, "find_engine", lambda: "/opt/llama-server")
    monkeypatch.setattr(engine, "_ready_model_id", lambda: 7)
    activated = []
    monkeypatch.setattr(models, "activate", lambda mid: activated.append(mid))
    monkeypatch.setattr(llamacpp.managed, "wait_ready", lambda timeout=0: True)
    monkeypatch.setattr(settings, "LOCAL_AI_BACKEND", "ollama")
    engine.state["status"] = "idle"
    engine.setup("small")
    for _ in range(100):
        if engine.state["status"] != "running":
            break
        time.sleep(0.05)
    assert engine.state["status"] == "ready", engine.state
    assert activated == [7] and settings.LOCAL_AI_BACKEND == "llamacpp" and settings.LLAMACPP_MODE == "managed"
    assert json.loads(runtime.RUNTIME_FILE.read_text())["LLAMACPP_MODE"] == "managed"
    with pytest.raises(engine.EngineError):
        engine.setup("huge")


def test_auto_setup_only_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "AI_AUTO_SETUP", "false")
    assert engine.maybe_auto_setup() is False
    monkeypatch.setattr(settings, "AI_AUTO_SETUP", "auto")
    assert engine.auto_setup_enabled() is False  # only the frozen release sets itself up


# ------------------------------------------------------------------ order / readiness
def test_scheduled_crawls_wait_for_tor_then_resume(monkeypatch):
    ready = {"v": False}
    monkeypatch.setattr(readiness, "tor_state", lambda force=False: {"ready": ready["v"], "reason": "no tor"})
    submitted = []
    sub = lambda **kw: submitted.append(kw)  # noqa: E731
    readiness._deferred.clear()
    assert readiness.defer_or_run(5, sub) == "deferred" and readiness.defer_or_run(6, sub) == "deferred"
    assert submitted == [] and readiness.deferred() == [5, 6]
    assert readiness.resume_deferred(sub) == 0  # still not ready
    ready["v"] = True
    assert readiness.resume_deferred(sub) == 2 and [s["target_id"] for s in submitted] == [5, 6]
    assert readiness.deferred() == [] and readiness.defer_or_run(7, sub) == "queued"


def test_manual_crawl_without_tor_is_refused_clearly(client, monkeypatch):
    monkeypatch.setattr(settings, "TOR_REQUIRED", True)
    monkeypatch.setattr("darkweb_monitor.crawler.tor_client.tor_status",
                        lambda force=False, max_age=300: {"is_tor": False, "reachable": True, "proxy": "127.0.0.1:9050",
                                                          "error": "SSLEOFError"})
    r = client.post("/api/crawl", json={"url": "http://" + "a" * 56 + ".onion"})
    assert r.status_code == 409 and "Tor is not connected" in r.json()["detail"] and "bridges" in r.json()["detail"]


def test_setup_checklist_is_ordered_and_points_to_next_step(client):
    steps = client.get("/api/setup/checklist").json()["steps"]
    assert [s["id"] for s in steps] == ["tor", "ai", "org", "watch", "targets", "crawl", "sources"]
    assert steps[0]["done"]  # TOR_REQUIRED=false in tests
    assert next(s for s in steps if s["next"])["id"] == "org"


def test_startup_runs_phases_in_order(monkeypatch):
    order = []
    import darkweb_monitor.scheduler.jobs as jobs
    from darkweb_monitor.ai import models
    monkeypatch.setattr(tor_manager, "autostart", lambda: order.append("tor"))
    monkeypatch.setattr(models, "autostart", lambda: order.append("ai"))
    monkeypatch.setattr(engine, "maybe_auto_setup", lambda: False)
    monkeypatch.setattr(jobs, "start_scheduler", lambda: order.append("scheduler"))
    readiness.boot.update(done=[], errors={})
    readiness.startup()
    assert order == ["tor", "ai", "scheduler"] and readiness.boot["done"] == ["database", "tor", "ai", "scheduler"]


# ------------------------------------------------------------------ assistant & suggestions
def test_help_search_understands_turkish():
    from darkweb_monitor.assistant import kb
    assert kb.search("Tor bağlantısı yok köprü")[0]["id"] == "tor"
    assert kb.search("model not found hatası")[0]["id"] in ("ai", "troubleshoot")


def test_suggestions_and_recommendations(client):
    from darkweb_monitor.storage.db import session_scope
    from darkweb_monitor.storage.models import Alert
    with session_scope() as s:
        s.add(Alert(title="leak", severity="critical", status="new", risk_score=80, threat_class="credential_leak"))
    d = client.get("/api/assistant/suggestions").json()
    labels = [q["label"] for q in d["queries"]]
    assert any("riskiest open alert" in x for x in labels) and any("credential leaks" in x for x in labels)
    assert any(q["kind"] == "help" for q in d["queries"])
    assert d["recommendations"][0]["level"] == "high" and "organisation" in d["recommendations"][0]["text"]


def test_assistant_answers_from_the_guide_without_a_model(client):
    from darkweb_monitor.analyst import service
    from darkweb_monitor.analyst.agent import RulesAdapter
    service.set_adapter(RulesAdapter())
    try:
        sid = client.post("/api/assistant/ask", json={"question": "Tor bağlanmıyor, ne yapmalıyım?"}).json()["id"]
        for _ in range(100):
            s = client.get(f"/api/analyst/sessions/{sid}").json()
            if s["status"] not in ("queued", "running"):
                break
            time.sleep(0.05)
        assert s["agent"] == "assistant" and s["status"] == "idle", s
        answers = [e["payload"]["content"] for e in s["events"]
                   if e["type"] == "assistant/message" and not e["payload"].get("tool_calls")]
        assert answers and "Tor" in answers[-1] and "Connect" in answers[-1]
    finally:
        service.set_adapter(None)


def test_ui_assets_and_icon(client):
    assert client.get("/ui/assist.js").status_code == 200
    assert client.get("/ui/icon.svg").headers["content-type"].startswith("image/svg+xml")
    ico = client.get("/favicon.ico")
    assert ico.status_code == 200 and ico.content[:4] == b"\x00\x00\x01\x00"
    assert client.get("/ui/../config/settings.py").status_code == 404
    assert client.get("/api/tor/manager").json()["status"] in ("stopped", "failed")
    assert "catalog" in client.get("/api/ai/engine").json()
