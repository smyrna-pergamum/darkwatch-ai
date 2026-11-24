import json
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from config.settings import settings
from darkweb_monitor.ai import providers
from darkweb_monitor.ai.router import AIRouter
from darkweb_monitor.ai import router as router_mod
from darkweb_monitor.analyst import service
from darkweb_monitor.analyst.agent import RulesAdapter
from darkweb_monitor.api.main import app
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import Alert


class FakeOpenAI(BaseHTTPRequestHandler):
    requests = []

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/models"):
            return self._send({"data": [{"id": "qwen2.5-3b-instruct"}, {"id": "phi-3-mini"}]})
        if self.path.endswith("/props"):
            return self._send({"default_generation_settings": {"n_ctx": 2048}})
        self._send({}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        FakeOpenAI.requests.append(body)
        self._send({"choices": [{"message": {"role": "assistant", "content": '{"ok": true, "summary": "s", "severity": "low"}'}}]})

    def log_message(self, *a):
        pass


@pytest.fixture
def lmstudio():
    srv = HTTPServer(("127.0.0.1", 0), FakeOpenAI)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "OLLAMA_ENABLED", False)
    providers.invalidate()
    with TestClient(app) as c:
        yield c
    providers.invalidate()


def fake_gguf(path=None) -> bytes:
    def s(x):
        b = x.encode()
        return struct.pack("<Q", len(b)) + b
    data = b"GGUF" + struct.pack("<IQQ", 3, 0, 3)
    data += s("general.architecture") + struct.pack("<I", 8) + s("llama")
    data += s("general.file_type") + struct.pack("<I", 4) + struct.pack("<I", 15)
    data += s("llama.context_length") + struct.pack("<I", 4) + struct.pack("<I", 8192)
    return data + b"\0" * 1024


def test_openai_compatible_provider_flow(client, lmstudio):
    assert "lmstudio" in client.get("/api/ai/presets").json()
    r = client.post("/api/ai/providers", json={"name": "LM Studio", "preset": "lmstudio", "base_url": lmstudio,
                                               "model": "qwen2.5-3b-instruct"})
    assert r.status_code == 201 and r.json()["trust"] == "local"   # loopback -> local
    key = r.json()["key"]
    t = client.post("/api/ai/providers/test", json={"key": key}).json()
    assert t["ok"], t
    assert "phi-3-mini" in t["models"]
    assert client.get(f"/api/ai/providers/{key}/models").json() == ["phi-3-mini", "qwen2.5-3b-instruct"]
    lst = client.get("/api/ai/providers?check=true").json()
    p = next(x for x in lst["providers"] if x["key"] == key)
    assert p["available"] and p["detected_window"] == 2048          # from llama-server style /props
    assert key in lst["routing"]["raw"]                               # local -> may see raw content
    # the router now uses it for raw page analysis, with a 2k budget -> chunked
    router_mod.set_router(AIRouter())
    FakeOpenAI.requests.clear()
    res = router_mod.get_router().analyze_page("u", "t", "data " * 4000, [])
    assert res["severity"] == "low" and len([r for r in FakeOpenAI.requests if "Analyse" in r["messages"][-1]["content"]]) > 1
    # remote provider is never used for raw tasks
    r2 = client.post("/api/ai/providers", json={"name": "Groq", "preset": "groq", "api_key": "sk-test-123456789"})
    assert r2.json()["trust"] == "remote"
    lst = client.get("/api/ai/providers").json()
    assert r2.json()["key"] not in lst["routing"]["raw"] and r2.json()["key"] in lst["routing"]["derived"]
    assert next(x for x in lst["providers"] if x["key"] == r2.json()["key"])["api_key_hint"] == "sk-…789"
    assert client.patch(f"/api/ai/providers/{key}", json={"enabled": False}).status_code == 200
    assert client.patch("/api/ai/providers/env:ollama", json={"enabled": False}).status_code == 400
    assert client.delete(f"/api/ai/providers/{r2.json()['key']}").status_code == 200


def test_gguf_upload_register_activate_delete(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "MODELS_DIR", str(tmp_path / "models"))
    r = client.put("/api/ai/models/upload?filename=tiny-q4.gguf", content=fake_gguf(),
                   headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 201, r.text
    m = r.json()
    assert m["meta"]["general.architecture"] == "llama" and m["meta"]["quantization"] == "Q4_K_M"
    assert m["meta"]["llama.context_length"] == 8192
    bad = client.put("/api/ai/models/upload?filename=evil.gguf", content=b"MZ\x90\x00" + b"x" * 100)
    assert bad.status_code == 400 and not (tmp_path / "models" / "evil.gguf").exists()
    ext = tmp_path / "ext.gguf"
    ext.write_bytes(fake_gguf())
    reg = client.post("/api/ai/models/register", json={"path": str(ext)})
    assert reg.status_code == 201
    assert client.post("/api/ai/models/register", json={"path": str(tmp_path / "none.gguf")}).status_code == 400
    assert client.post(f"/api/ai/models/{m['id']}/activate").json()["ok"]
    lst = client.get("/api/ai/models").json()
    assert [x["active"] for x in lst["models"] if x["id"] == m["id"]] == [True]
    assert lst["llamacpp"]["active_model"] == "tiny-q4.gguf"
    assert client.post("/api/ai/models/download", json={"url": "http://evil.example/x.gguf"}).status_code == 400
    assert client.delete(f"/api/ai/models/{reg.json()['id']}").json()["file_deleted"] is False  # registered path kept
    assert ext.exists()
    assert client.delete(f"/api/ai/models/{m['id']}").json()["file_deleted"] is True


def test_analyst_api(client):
    with session_scope() as s:
        a = Alert(title="hit", severity="high", matches=[{"kind": "domain", "value": "acme.com", "severity": "high"}])
        s.add(a)
        s.flush()
        aid = a.id
    service.set_adapter(RulesAdapter())
    try:
        st = client.get("/api/analyst/status").json()
        assert st["rule_based"] and {a["id"] for a in st["agents"]} == {"analyst", "assistant", "page-reader"}
        sid = client.post("/api/analyst/sessions", json={"alert_id": aid}).json()["id"]
        service._pool.submit(lambda: None).result(timeout=10)
        d = client.get(f"/api/analyst/sessions/{sid}").json()
        assert d["status"] == "done" and d["report"]["verdict"]
        assert [e["type"] for e in d["events"]][0] == "session/created"
        assert client.get(f"/api/analyst/sessions?alert_id={aid}").json()[0]["id"] == sid
        assert client.post(f"/api/analyst/sessions/{sid}/messages", json={"text": "why?"}).status_code == 202
        service._pool.submit(lambda: None).result(timeout=10)
        assert client.get("/api/analyst/approvals").json() == []
    finally:
        service.set_adapter(None)
