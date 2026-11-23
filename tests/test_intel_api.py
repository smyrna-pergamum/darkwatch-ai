"""Integration: crawl -> classification, tenant attribution, risk, evidence,
forum actors, change detection; tenant-scoped API; IncidentForge escalation."""
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from config.settings import settings
from darkweb_monitor.api.main import app
from darkweb_monitor.pipeline import run_crawl
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import Alert, Page
from darkweb_monitor.storage.models_intel import ActorHandle, Evidence, ThreatActor
from conftest import ONION_A, FakeClient

BASE = f"http://{ONION_A}"
THREAD = """<html><title>[SALE] acme-corp.com network access</title><body>
<div class="post"><div class="author"><strong>initial_broker</strong><time datetime="2026-11-20T08:00:00">20 Nov</time></div>
 <div class="content">Selling VPN access to acme-corp.com, domain admin. revenue: $900M.
 admin@acme-corp.com:Winter2026! Contact telegram: @ib_broker1</div></div>
<div class="post"><div class="author"><strong>buyer42</strong></div><div class="content">pm sent</div></div>
</body></html>"""


def _site(thread=THREAD):
    return {f"{BASE}/": '<html><title>Forum</title><body><a href="/t/1">thread</a></body></html>',
            f"{BASE}/t/1": thread}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _crawl(site):
    return run_crawl(f"{BASE}/", depth=1, spider_client=FakeClient(site))


def _setup_org(client, **extra):
    r = client.post("/api/orgs", json={"name": "ACME Corp", "sector": "manufacturing", **extra,
                                       "assets": [{"asset_type": "domain", "value": "acme-corp.com"},
                                                  {"asset_type": "brand", "value": "ab"}]})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["assets"] == 1 and body["asset_errors"][0]["value"] == "ab"
    return body["id"]


def test_crawl_enriches_alert_end_to_end(client):
    oid = _setup_org(client)
    res = _crawl(_site())
    assert res["alerts_raised"] == 1
    with session_scope() as s:
        a = s.query(Alert).one()
        assert a.threat_class == "initial_access"
        assert a.risk_score > 50 and any("known threat actor" in f["factor"] for f in a.risk_factors)
        assert a.triage["classification"]["threat_class"] == "initial_access"
        ev = s.query(Evidence).filter_by(alert_id=a.id).one()  # auto-captured (severity >= high)
        assert ev.kind == "page_snapshot"
        actor = s.query(ThreatActor).one()
        assert actor.name == "initial_broker"
        assert s.query(ActorHandle).filter_by(platform="telegram", value="ib_broker1").count() == 1
        aid = a.id

    intel = client.get(f"/api/alerts/{aid}/intel").json()
    assert intel["organizations"] == [{"id": oid, "name": "ACME Corp"}] and intel["actors"][0]["name"] == "initial_broker"
    org = client.get(f"/api/orgs/{oid}").json()
    assert org["open_alerts"] == 1 and org["risk_score"] > 0
    exp = client.get(f"/api/orgs/{oid}/exposure").json()
    assert exp["exposed_credentials"][0]["value"].startswith("admin@acme-corp.com:W")
    assert "Winter2026!" not in str(exp)  # passwords are never stored
    assert exp["threat_actors"][0]["name"] == "initial_broker"
    assert client.get(f"/api/orgs/{oid}/alerts?status=open").json()["total"] == 1

    g = client.get(f"/api/graph?center=org:{oid}&depth=3").json()
    types = {n["type"] for n in g["nodes"]}
    assert {"org", "asset", "alert", "actor", "site"} <= types
    assert client.get("/api/graph?center=bogus:1").status_code == 422

    actors = client.get("/api/actors?q=ib_broker").json()
    assert actors["total"] == 1
    prof = client.get(f"/api/actors/{actors['items'][0]['id']}").json()
    assert prof["profile"]["targets"][0]["organization"] == "ACME Corp"
    assert client.get("/api/intel/overview").json()["open_by_class"] == {"initial_access": 1}


def test_change_detection_records_diff(client):
    _crawl(_site())
    _crawl(_site(THREAD.replace("domain admin", "domain admin + backups")))
    with session_scope() as s:
        p = s.query(Page).filter_by(url=f"{BASE}/t/1").one()
        pid = p.id
    ch = client.get(f"/api/pages/{pid}/changes").json()
    assert ch["changed"] and ch["change_summary"]["added_count"] >= 1
    assert any("backups" in x for x in ch["change_summary"]["added"])


def test_evidence_api(client):
    _setup_org(client)
    _crawl(_site())
    aid = client.get("/api/alerts").json()["items"][0]["id"]
    ev = client.get(f"/api/evidence?alert_id={aid}").json()["items"][0]
    v = client.post(f"/api/evidence/{ev['id']}/verify").json()
    assert v["ok"] and v["custody_events"] >= 1
    r = client.get(f"/api/evidence/{ev['id']}/download")
    assert r.status_code == 200 and r.headers["x-evidence-sha256"] == ev["sha256"]
    assert client.post(f"/api/evidence/{ev['id']}/hold", json={"legal_hold": True}).json()["legal_hold"]
    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/alerts/{aid}/evidence/bundle").content))
    assert "manifest.json" in z.namelist()
    chain = client.get(f"/api/evidence/{ev['id']}").json()["custody"]
    assert [c["action"] for c in chain] == ["captured", "verified", "exported", "hold", "exported"]
    assert client.post(f"/api/evidence/{ev['id']}/verify").json()["chain_ok"]
    manual = client.post(f"/api/alerts/{aid}/evidence", json={"note": "analyst copy"})
    assert manual.status_code == 201 and manual.json()["id"] == ev["id"]  # same observation -> same item


def test_tenant_keys_are_scoped(client, monkeypatch):
    oid = _setup_org(client)
    other = client.post("/api/orgs", json={"name": "Other Inc"}).json()["id"]
    key = client.post(f"/api/orgs/{oid}/keys", json={"name": "portal"}).json()["key"]
    monkeypatch.setattr(settings, "API_KEY", "admin-secret")
    t = {"X-API-Key": key}
    assert client.get(f"/api/orgs/{oid}", headers=t).json()["role"] == "tenant"
    assert client.get(f"/api/orgs/{oid}/risk", headers=t).status_code == 200
    assert client.post(f"/api/orgs/{oid}/assets/bulk", headers=t,
                       json={"asset_type": "employee_email", "text": "a@acme-corp.com\nb@acme-corp.com, bad"}).json()["added"] == 2
    assert client.get(f"/api/orgs/{other}", headers=t).status_code == 403
    assert client.get("/api/orgs", headers=t).status_code == 401          # admin only
    assert client.get("/api/alerts", headers=t).status_code == 401        # global API is admin only
    assert client.get(f"/api/orgs/{oid}", headers={"X-API-Key": "dwk_nope"}).status_code == 401
    assert client.get(f"/api/orgs/{oid}").status_code == 401
    admin = {"X-API-Key": "admin-secret"}
    kid = client.get(f"/api/orgs/{oid}/keys", headers=admin).json()[0]["id"]
    client.delete(f"/api/orgs/{oid}/keys/{kid}", headers=admin)
    assert client.get(f"/api/orgs/{oid}", headers=t).status_code == 401  # revoked
    assert client.delete(f"/api/orgs/{other}", headers=admin).json()["deleted"] == other


def test_incidentforge_escalation(client, monkeypatch):
    _setup_org(client)
    _crawl(_site())
    aid = client.get("/api/alerts").json()["items"][0]["id"]
    assert client.post(f"/api/alerts/{aid}/incidentforge").status_code == 400  # not configured
    sent = {}

    class Resp:
        status_code = 201
        text = ""

        def json(self):
            return {"id": "INC-2026-0042"}

    def fake_post(self, url, json=None, headers=None, timeout=None, verify=None):
        sent.update(url=url, payload=json, headers=headers)
        return Resp()
    monkeypatch.setattr("requests.Session.post", fake_post)
    monkeypatch.setattr(settings, "INCIDENTFORGE_URL", "https://forge.test")
    monkeypatch.setattr(settings, "INCIDENTFORGE_API_KEY", "tok")
    pre = client.get(f"/api/alerts/{aid}/incidentforge/preview").json()
    assert pre["schema"] == "darkwatch.incident/1" and "content_b64" not in pre["evidence"][0]
    r = client.post(f"/api/alerts/{aid}/incidentforge")
    assert r.json()["incident_ref"] == "INC-2026-0042"
    p = sent["payload"]
    assert sent["url"] == "https://forge.test/api/v1/incidents" and sent["headers"]["Authorization"] == "Bearer tok"
    assert p["category"] == "initial_access" and p["organizations"][0]["name"] == "ACME Corp"
    assert p["threat_actors"][0]["name"] == "initial_broker" and p["evidence"][0]["content_b64"]
    assert client.get(f"/api/alerts/{aid}").json()["incident_ref"] == "INC-2026-0042"
    ev = client.get(f"/api/evidence?alert_id={aid}").json()["items"][0]
    assert client.get(f"/api/evidence/{ev['id']}").json()["custody"][-1]["action"] == "escalated"


def test_rescore_and_ui_asset(client):
    _setup_org(client)
    _crawl(_site())
    assert client.post("/api/intel/rescore").json() == {"alerts": 1, "organizations": 1}
    aid = client.get("/api/alerts").json()["items"][0]["id"]
    assert client.post(f"/api/alerts/{aid}/rescore").json()["threat_class"] == "initial_access"
    assert client.get("/ui/intel.js").status_code == 200
    assert client.get("/ui/..%2Fconfig%2Fsettings.py").status_code == 404
    assert len(client.get("/api/threat-classes").json()) >= 10


def test_tenant_sees_only_own_matches_on_shared_alert(client, monkeypatch):
    a = client.post("/api/orgs", json={"name": "A Corp", "assets": [{"asset_type": "domain", "value": "acme-corp.com"}]}).json()["id"]
    b = client.post("/api/orgs", json={"name": "B Corp", "assets": [{"asset_type": "brand", "value": "initial_broker"}]}).json()["id"]
    _crawl(_site())
    key = client.post(f"/api/orgs/{b}/keys", json={}).json()["key"]
    monkeypatch.setattr(settings, "API_KEY", "admin")
    items = client.get(f"/api/orgs/{b}/alerts", headers={"X-API-Key": key}).json()["items"]
    assert items and all(m["value"] == "initial_broker" for m in items[0]["matches"])
    assert items[0]["title"].startswith("Watchlist hit [initial_broker] on")  # A's watch terms are hidden
    assert items[0]["analyst_note"] == "" and "domain" not in str(items[0]["risk_factors"])
    assert client.post(f"/api/orgs/{b}/assets", headers={"X-API-Key": key},
                       json={"asset_type": "domain", "value": "acme-corp.com"}).status_code == 409
    assert client.post(f"/api/orgs/{b}/assets", headers={"X-API-Key": key},
                       json={"asset_type": "regex", "value": "(a+)+$"}).status_code == 422
    assert a != b
