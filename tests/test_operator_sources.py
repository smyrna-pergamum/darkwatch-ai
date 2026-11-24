"""Intel-source configuration, new sources, Ahmia parsing, ad-hoc queries,
natural-language missions and the operator agent (rule-based)."""
import time

import pytest
from fastapi.testclient import TestClient

from config import intel_store
from config.settings import settings
from darkweb_monitor.analyst import service
from darkweb_monitor.analyst.agent import RulesAdapter
from darkweb_monitor.analyst.ops_rules import extract_terms, interval_of, plan
from darkweb_monitor.api.main import app
from darkweb_monitor.crawler.parsers import onion_checksum_ok
from darkweb_monitor.sources import runner as src_runner
from darkweb_monitor.sources.ahmia import AhmiaSource, parse_results
from darkweb_monitor.sources.base import Finding, Source
from darkweb_monitor.sources.custom import CustomSource, validate_custom
from darkweb_monitor.sources.extra import HudsonRockSource, LeakCheckSource
from darkweb_monitor.sources.onionsearch import engines, parse_engine
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import AgentSession, Alert, Task, WatchItem
from darkweb_monitor.tasks import mission_interval
from darkweb_monitor.watchlist import WatchTerm

AHMIA = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd"
DDG = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
TORPROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid"


class Dummy(Source):
    name, label, kinds = "dummy", "Dummy", ("domain", "email", "brand")

    def enabled(self):
        return True

    def run(self, terms):
        return [Finding(source="dummy", key=f"k:{t.value}", title=f"found {t.value}", description="d",
                        severity="high", matched=t) for t in terms], len(terms)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(src_runner, "SOURCES", [Dummy()])
    service.set_adapter(RulesAdapter())
    with TestClient(app) as c:
        yield c
    service.set_adapter(None)


def wait_session(sid, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        with session_scope() as s:
            st = s.get(AgentSession, sid).status
        if st not in ("queued", "running"):
            return st
        time.sleep(0.1)
    raise AssertionError("session did not finish")


def test_onion_checksum():
    assert onion_checksum_ok(AHMIA) and onion_checksum_ok(DDG + ".onion") and onion_checksum_ok(TORPROJECT)
    assert not onion_checksum_ok("a" * 56)
    for _, url in engines():  # built-in engine list only contains valid addresses
        assert onion_checksum_ok(url.split("//")[1].split(".onion")[0])


def test_ahmia_parse_results():
    html = f"""<ol><li class="result"><h4><a href="/search/redirect?search_term=x&redirect_url=http://{DDG}.onion/">DuckDuckGo</a></h4>
      <p>Privacy search</p><cite>{DDG}.onion</cite></li>
      <li class="result"><h4><a href="/search/redirect?redirect_url=http://{AHMIA}.onion/">self</a></h4></li>
      <li class="result"><a href="http://{'a' * 56}.onion/">fake</a></li></ol>"""
    res = parse_results(html, own=AHMIA)
    assert [r["onion"] for r in res] == [DDG + ".onion"] and res[0]["title"] == "DuckDuckGo"
    hits = parse_engine(f'<a href="http://{TORPROJECT}.onion/">Tor Project</a> text {DDG}.onion', own="")
    assert hits[TORPROJECT] == "Tor Project" and DDG in hits


def test_ahmia_modes(monkeypatch):
    monkeypatch.setattr(settings, "AHMIA_MODE", "auto")
    monkeypatch.setattr("darkweb_monitor.sources.ahmia.tor_usable", lambda: (False, "down"))
    assert AhmiaSource().endpoints() == [(settings.AHMIA_CLEARNET_URL, False)]
    monkeypatch.setattr(settings, "AHMIA_MODE", "tor")
    with pytest.raises(Exception, match="Tor is required"):
        AhmiaSource().endpoints()
    monkeypatch.setattr("darkweb_monitor.sources.ahmia.tor_usable", lambda: (True, ""))
    monkeypatch.setattr(settings, "AHMIA_MODE", "auto")
    assert [v for _, v in AhmiaSource().endpoints()] == [True, False]


def test_new_sources(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    monkeypatch.setattr(Source, "get_json", lambda self, s, url, **kw: (
        {"employees": 3, "users": 10, "third_parties": 0, "total": 13} if "domain" in url else
        {"stealers": [{"computer_name": "PC1", "date_compromised": "2026-10-01T00:00:00"}]}))
    f, q = HudsonRockSource().run([WatchTerm("domain", "acme.com"), WatchTerm("email", "ceo@acme.com")])
    assert q == 2 and f[0].severity == "critical" and "3 employee" in f[0].title and "infostealer" in f[1].title
    monkeypatch.setattr(settings, "LEAKCHECK_API_KEY", "k")
    monkeypatch.setattr(Source, "get_json", lambda self, s, url, **kw: {"success": True, "result": [
        {"email": "a@acme.com", "source": {"name": "Combo1"}, "fields": ["password"], "password": "x"},
        {"email": "b@acme.com", "source": {"name": "Combo1"}, "fields": []}]})
    f, _ = LeakCheckSource().run([WatchTerm("domain", "acme.com")])
    assert len(f) == 1 and f[0].severity == "high" and "x" not in f[0].description.split("Accounts")[0]
    assert LeakCheckSource().enabled()


def test_custom_source(monkeypatch):
    cfg = validate_custom({"name": "MyAPI".lower(), "url": "https://api.example/search?q={term}&k={key}",
                           "api_key": "abc", "results_path": "data.items", "title_field": "name", "id_field": "id"})
    seen = {}

    def fake(self, s, url, **kw):
        seen["url"] = url
        return {"data": {"items": [{"id": 1, "name": "leak one"}, {"id": 2, "name": "leak two"}]}}
    monkeypatch.setattr(Source, "get_json", fake)
    f, _ = CustomSource(cfg).run([WatchTerm("domain", "acme.com")])
    assert len(f) == 2 and f[0].title == "myapi: leak one" and "q=acme.com&k=abc" in seen["url"]
    with pytest.raises(ValueError):
        validate_custom({"name": "x y", "url": "ftp://x"})


def test_settings_api_masks_secrets(client):
    r = client.put("/api/sources/settings", json={"values": {"VIRUSTOTAL_API_KEY": "secret-key-1234",
                                                                 "AHMIA_ENABLED": False}})
    assert r.status_code == 200 and settings.VIRUSTOTAL_API_KEY == "secret-key-1234"
    assert intel_store._read()["settings"]["AHMIA_ENABLED"] is False
    body = client.get("/api/sources").text
    assert "secret-key-1234" not in body and "1234" in body
    assert client.put("/api/sources/settings", json={"values": {"API_KEY": "x"}}).status_code == 422
    r = client.post("/api/sources/custom", json={"name": "corp-leaks", "url": "https://x.example/{term}",
                                                 "api_key": "zzz-secret"})
    assert r.status_code == 201
    assert "zzz-secret" not in client.get("/api/sources").text
    assert client.delete("/api/sources/custom/custom:corp-leaks").status_code == 200
    settings.VIRUSTOTAL_API_KEY = ""
    settings.AHMIA_ENABLED = False


def test_adhoc_query(client):
    r = client.post("/api/sources/query", json={"terms": ["acme.com", "ceo@acme.com"]}).json()
    assert [t["kind"] for t in r["terms"]] == ["domain", "email"]
    assert len(r["results"][0]["findings"]) == 2
    with session_scope() as s:
        assert s.query(Alert).count() == 0  # not saved unless asked
    client.post("/api/sources/query", json={"terms": ["acme.com"], "save": True})
    with session_scope() as s:
        assert s.query(Alert).count() == 1


def test_rules_planner():
    text = "Her gün acme.com ve ceo@acme.com için Ahmia ve onion sitelerinde \"Acme Corp\" ara"
    assert extract_terms(text) == ["ceo@acme.com", "acme.com", "Acme Corp"]
    assert interval_of(text) == "daily" and mission_interval("daily") == 1440 and mission_interval(5) == 60
    names = [c["name"] for c in plan(text)]
    assert names.count("search_onions") == 3 and "create_mission" in names
    assert "create_mission" not in [c["name"] for c in plan(text + "\n\n[Context]\n[Scheduled run of mission #1]")]


def test_chat_operator_and_mission(client):
    sid = client.post("/api/analyst/sessions", json={"question": "acme.com için sızıntı ara ve her gün izle"}).json()["id"]
    assert wait_session(sid) in ("idle", "done")
    d = client.get(f"/api/analyst/sessions/{sid}").json()
    assert d["agent"] == "operator"
    text = " ".join(str(e["payload"]) for e in d["events"])
    assert "found acme.com" in text and "Monitoring mission" in text
    with session_scope() as s:
        m = s.query(Task).filter_by(kind="mission").one()
        assert m.status == "approved" and m.payload["interval_min"] == 1440 and m.due_at


def test_mission_api(client):
    with session_scope() as s:
        s.add(WatchItem(kind="domain", value="acme.com"))
    r = client.post("/api/missions", json={"instruction": "acme.com için tüm kaynaklarda kontrol et", "every": "6h"})
    assert r.status_code == 201 and r.json()["session_id"]
    sid = r.json()["session_id"]
    assert wait_session(sid) in ("idle", "done")
    with session_scope() as s:
        t = s.get(Task, r.json()["id"])
        assert t.status == "approved" and t.payload["runs"] == 1 and t.payload["interval_min"] == 360
        assert s.query(Alert).count() == 1  # mission runs store findings
        assert s.query(Task).filter_by(kind="mission").count() == 1  # no recursive missions
    assert client.get("/api/tasks?kind=mission").json()["items"][0]["kind"] == "mission"
    assert client.post(f"/api/tasks/{r.json()['id']}/run").json()["session_id"]
    assert client.post("/api/missions", json={"instruction": "acme.com için tüm kaynaklarda kontrol et",
                                              "every": "6h"}).status_code == 409
