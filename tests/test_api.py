import json

import pytest
from fastapi.testclient import TestClient

from config.settings import settings
from darkweb_monitor import runner as runner_mod
from darkweb_monitor.api.main import app
from darkweb_monitor.pipeline import run_crawl
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import Alert, Target
from conftest import ONION_A, FakeClient


@pytest.fixture
def client(site, monkeypatch):
    class SyncManager(runner_mod.RunManager):
        """Runs crawls synchronously against the fake site."""
        def _execute(self, run_id, tid, keywords, depth, mode, goal, max_pages, trigger, flag):
            run_crawl(target_id=tid, run_id=run_id, depth=depth, mode=mode, goal=goal,
                      max_pages=max_pages, trigger=trigger, spider_client=FakeClient(site))

        def submit(self, **kw):
            rid = super().submit(**kw)
            self._pool.shutdown(wait=True)
            return rid
    monkeypatch.setattr(runner_mod, "_manager", SyncManager())
    with TestClient(app) as c:
        yield c


def test_auth(client, monkeypatch):
    assert client.get("/api/stats").status_code == 200
    monkeypatch.setattr(settings, "API_KEY", "s3cret")
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/health").status_code == 200
    r = client.get("/")
    assert "DarkWatch AI" in r.text and "Content-Security-Policy" in r.headers


def test_no_wildcard_cors(client):
    r = client.get("/api/stats", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_target_watch_crawl_alert_flow(client):
    r = client.post("/api/targets", json={"url": ONION_A, "label": "forum", "crawl_mode": "standard",
                                          "schedule_interval_min": 360, "depth": 2})
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    assert client.post("/api/targets", json={"url": ONION_A}).status_code == 409
    assert client.post("/api/targets", json={"url": ONION_A + "x", "schedule_cron": "nope"}).status_code == 422
    assert client.post("/api/watchlist", json={"kind": "keyword", "value": "ab"}).status_code == 422
    assert client.post("/api/watchlist", json={"kind": "domain", "value": "acme-corp.com", "severity": "critical"}).status_code == 201

    r = client.post(f"/api/targets/{tid}/crawl")
    assert r.status_code == 202
    run = client.get(f"/api/runs/{r.json()['run_id']}").json()
    assert run["status"] == "done" and run["alerts"] == 1 and len(run["pages_list"]) == 4

    alerts = client.get("/api/alerts?status=open").json()
    assert alerts["total"] == 1 and alerts["items"][0]["severity"] == "critical"
    aid = alerts["items"][0]["id"]
    assert client.patch(f"/api/alerts/{aid}", json={"status": "acknowledged", "analyst_note": "checking"}).status_code == 200
    assert client.get(f"/api/alerts/{aid}").json()["analyst_note"] == "checking"
    assert client.post("/api/alerts/bulk", json={"ids": [aid], "status": "resolved"}).json()["updated"] == 1

    st = client.get("/api/stats").json()
    assert st["pages"] == 4 and st["indicators"] > 0
    assert client.get("/api/search?q=acme").json()["pages"]

    pages = client.get("/api/pages?changed=true").json()
    pid = pages["items"][0]["id"]
    assert "content" in client.get(f"/api/pages/{pid}").json()

    inds = client.get("/api/indicators?watch_only=true").json()
    assert inds["total"] >= 1
    stix = json.loads(client.get("/api/indicators/export?fmt=stix").text)
    assert stix["type"] == "bundle" and any(o["type"] == "indicator" for o in stix["objects"])
    misp = client.get("/api/indicators/export?fmt=misp").json()
    assert misp["Event"]["Attribute"]
    assert client.get("/api/indicators/export?fmt=csv").text.startswith("type,value")

    assert client.patch(f"/api/targets/{tid}", json={"active": False, "crawl_mode": "agent"}).json()["crawl_mode"] == "agent"
    assert client.delete(f"/api/targets/{tid}?purge=true").status_code == 200
    with session_scope() as s:
        assert s.query(Target).count() == 0 and s.query(Alert).count() == 1  # alerts survive
    assert client.get("/api/audit").json()["total"] > 0


def test_tasks_approval_creates_target(client):
    r = client.post("/api/tasks", json={"kind": "add_target", "title": "watch",
                                        "payload": {"url": "http://" + "d" * 56 + ".onion/", "mode": "agent"}})
    assert r.status_code == 201
    tid = r.json()["id"]
    assert client.get("/api/tasks?status=proposed").json()["total"] == 1
    assert client.post(f"/api/tasks/{tid}/approve").json()["status"] == "done"
    t = client.get("/api/targets").json()[0]
    assert t["source"] == "ai" and t["crawl_mode"] == "agent"
    bad = client.post("/api/tasks", json={"kind": "add_target", "payload": {"url": "http://clearnet.com"}})
    assert bad.status_code == 422


def test_status_and_sources(client):
    s = client.get("/api/status").json()
    assert s["ai"]["raw_tasks_provider"] == [] and s["tor"]["enabled"] is False
    names = {x["name"] for x in client.get("/api/sources").json()["sources"]}
    assert names == {"hibp", "intelx", "ransomware", "ahmia"}
