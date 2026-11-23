"""Unit tests: classification, risk, forum parsing, change diff, evidence, actors, graph, orgs."""
import gzip
import zipfile
import io

import pytest

from darkweb_monitor.crawler.forum import contacts_in, parse_forum
from darkweb_monitor.intel import actors as actorsvc
from darkweb_monitor.intel import evidence as evsvc
from darkweb_monitor.intel import orgs as orgsvc
from darkweb_monitor.intel.changes import diff_summary
from darkweb_monitor.intel.classify import classify
from darkweb_monitor.intel.graph import build_graph
from darkweb_monitor.intel.risk import alert_risk, compute_org_risk, level_for
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import Alert, Indicator, Page
from darkweb_monitor.storage.models_intel import AlertOrg, CustodyEvent, ThreatActor


# ------------------------------------------------------------------ classification
@pytest.mark.parametrize("text,source,expected", [
    ("LockBit leak site: ACME files will be published in 5 days unless ransom paid", "", "ransomware"),
    ("Selling RDP access to acme corp network, domain admin, revenue: $2B", "", "initial_access"),
    ("Fresh combo list email:pass 2M lines", "", "credential_leak"),
    ("Redline stealer logs cloud, daily updates", "", "malware"),
    ("We are looking for insiders working at banks, high reward", "", "insider"),
    ("hello world nothing here", "", "mention"),
    ("Ransomware group 'akira' lists victim 'ACME'", "ransomware", "ransomware"),
    ("x@acme.com appears in breach 'Foo'", "hibp", "credential_leak"),
])
def test_classify(text, source, expected):
    c = classify(text, source=source)
    assert c.threat_class == expected
    assert 0 < c.confidence <= 0.95 and c.signals


def test_classify_uses_ai_category_and_iocs():
    c = classify("new thread", ai_category="credentials", ioc_types=["credential"])
    assert c.threat_class == "credential_leak"
    assert any("AI category" in x for x in c.signals)


# ------------------------------------------------------------------ risk
def _alert(**kw):
    base = dict(title="t", description="", severity="high", status="new", matches=[], triage={}, occurrences=1,
                source="crawler", threat_class="")
    base.update(kw)
    return Alert(**base)


def test_alert_risk_is_explainable_and_bounded():
    low = alert_risk(_alert(severity="low"))[0]
    high, factors = alert_risk(_alert(severity="critical", threat_class="ransomware", occurrences=8,
                                      matches=[{"kind": "domain", "value": "acme.com"}],
                                      triage={"true_positive": True, "confidence": 0.9}), known_actor=True)
    assert low < high <= 100
    labels = " ".join(f["factor"] for f in factors)
    assert "ransomware" in labels and "domain" in labels and "known threat actor" in labels
    assert alert_risk(_alert(status="false_positive"))[0] == 0
    fp = alert_risk(_alert(triage={"true_positive": False, "confidence": 0.9}))[0]
    assert fp < alert_risk(_alert())[0]
    assert level_for(80) == "critical" and level_for(10) == "low"


def test_org_risk_aggregates_open_alerts_and_exposed_credentials():
    with session_scope() as s:
        org = orgsvc.create_org(s, "ACME Corp")
        orgsvc.add_asset(s, org.id, "domain", "acme-corp.com")
        empty = compute_org_risk(s, org.id)
        assert empty["score"] == 0 and empty["level"] == "low"
        a1 = _alert(severity="high", threat_class="credential_leak")
        a2 = _alert(severity="medium", title="second")
        s.add_all([a1, a2])
        s.flush()
        for a in (a1, a2):
            a.risk_score = alert_risk(a)[0]
            s.add(AlertOrg(alert_id=a.id, org_id=org.id))
        one = compute_org_risk(s, org.id)
        assert 0 < one["score"] < 100 and one["open_alerts"] == 2
        s.add(Indicator(ioc_type="credential", value="bob@acme-corp.com:h****2#abc", seen_count=1))
        s.flush()
        two = compute_org_risk(s, org.id)
        assert two["exposed_credentials"] == 1 and two["score"] > one["score"]
        a1.status = a2.status = "resolved"
        assert compute_org_risk(s, org.id)["open_alerts"] == 0


# ------------------------------------------------------------------ forum parsing
PHPBB = """<html><body>
<div class="post"><div class="author"><strong>dark_seller</strong> <time datetime="2026-11-01T10:00:00">1 Nov</time></div>
  <div class="content">Selling acme-corp.com VPN access. Contact telegram: @darkseller77 or jabber: ds@xmpp.is</div></div>
<div class="post"><div class="author"><strong>curious_guy</strong></div><div class="content">price?</div></div>
</body></html>"""

GENERIC = """<html><body><div class="thread">
<div class="message"><span class="username">vendorX</span><p>Fresh acme logs, tox: """ + "A" * 76 + """</p></div>
</div></body></html>"""


def test_parse_phpbb_forum():
    posts = parse_forum(PHPBB)
    assert [p.author for p in posts] == ["dark_seller", "curious_guy"]
    assert posts[0].posted.startswith("2026-11-01")
    assert ("telegram", "darkseller77") in posts[0].contacts and ("jabber", "ds@xmpp.is") in posts[0].contacts


def test_parse_generic_forum_and_contacts():
    posts = parse_forum(GENERIC)
    assert posts and posts[0].author == "vendorX" and posts[0].contacts[0][0] == "tox"
    assert contacts_in("telegram is great") == []
    assert parse_forum("<html><body>No posts here at all, just text.</body></html>") == []


# ------------------------------------------------------------------ change detection
def test_diff_summary():
    d = diff_summary("Welcome\nOld listing\nFooter", "Welcome\nNew: acme-corp.com dump\nFooter", ["acme-corp.com"])
    assert d["added"] == ["New: acme-corp.com dump"] and d["removed"] == ["Old listing"]
    assert d["watch_terms_added"] == ["acme-corp.com"] and d["kind"] in ("major", "rewritten")
    assert diff_summary("", "a")["kind"] == "new"


# ------------------------------------------------------------------ evidence
def _page_alert(s, content="secret leak acme"):
    p = Page(url="http://x.onion/t/1", title="Leak", content=content, content_hash="h", status_code=200)
    s.add(p)
    s.flush()
    a = Alert(title="Leak on x", severity="high", page_id=p.id, url=p.url, matches=[])
    s.add(a)
    s.flush()
    return p, a


def test_evidence_capture_verify_and_tamper_detection():
    with session_scope() as s:
        _, a = _page_alert(s)
        ev = evsvc.capture_for_alert(s, a, actor="tester")
        assert ev.kind == "page_snapshot" and len(ev.sha256) == 64
        assert evsvc.capture_for_alert(s, a).id == ev.id  # same content -> same item
        res = evsvc.verify(s, ev)
        assert res["ok"] and res["file_ok"] and res["chain_ok"]
        assert b"secret leak acme" in evsvc.read_content(ev)
        eid = ev.id
    with session_scope() as s:  # tamper with the custody log
        ce = s.query(CustodyEvent).filter_by(evidence_id=eid, seq=1).one()
        ce.detail = "edited"
    with session_scope() as s:
        res = evsvc.verify(s, s.get(evsvc.Evidence, eid), log=False)
        assert not res["chain_ok"] and not res["ok"]
        ev = s.get(evsvc.Evidence, eid)
        path = evsvc._resolve(ev)
    with gzip.open(path, "wb") as fh:  # tamper with the file
        fh.write(b"{}")
    with session_scope() as s:
        res = evsvc.verify(s, s.get(evsvc.Evidence, eid), log=False)
        assert not res["file_ok"] and "mismatch" in " ".join(res["problems"])


def test_evidence_bundle_and_source_record():
    with session_scope() as s:
        a = Alert(title="Ransomware group 'akira' lists victim 'ACME'", source="ransomware", severity="critical")
        s.add(a)
        s.flush()
        ev = evsvc.capture_for_alert(s, a)
        assert ev.kind == "source_record"
        data = evsvc.export_bundle(s, a.id, actor="tester")
        actions = [c.action for c in s.query(CustodyEvent).filter_by(evidence_id=ev.id)]
    z = zipfile.ZipFile(io.BytesIO(data))
    assert {"manifest.json", "SHA256SUMS"} <= set(z.namelist())
    assert ev.sha256 in z.read("SHA256SUMS").decode()
    assert actions == ["captured", "exported"]


# ------------------------------------------------------------------ actors
def test_actor_ingest_merge_and_profile():
    with session_scope() as s:
        _, a = _page_alert(s)
        posts = parse_forum(PHPBB)
        ids = actorsvc.ingest_forum_posts(s, posts, host="forum.onion", page_id=a.page_id,
                                          watch_terms=["acme-corp.com"], alert_id=a.id)
        assert len(ids) == 1  # only the post that mentions the asset
        actor = s.get(ThreatActor, ids[0])
        assert actor.name == "dark_seller"
        handles = {(h.platform, h.value) for h in s.query(actorsvc.ActorHandle).filter_by(actor_id=actor.id)}
        assert ("forum", "dark_seller@forum.onion") in handles and ("telegram", "darkseller77") in handles
        other = actorsvc.get_or_create(s, "DS-alias")
        actorsvc.add_handle(s, other, "telegram", "darkseller77")  # shared contact -> tagged link
        assert any("shares telegram" in t for t in other.tags)
        merged = actorsvc.merge(s, actor.id, other.id)
        assert "DS-alias" in merged.aliases
        assert actorsvc.get_or_create(s, "ds-alias").id == merged.id  # alias lookup
        prof = actorsvc.build_profile(s, merged)
        assert prof["venues"][0]["host"] == "forum.onion" and "dark_seller" in prof["summary"]
        r = Alert(title="Ransomware group 'Akira' lists victim 'ACME'", source="ransomware", severity="critical")
        s.add(r)
        s.flush()
        gid = actorsvc.ingest_ransomware_alert(s, r)
        assert s.get(ThreatActor, gid).kind == "ransomware_group"
        assert actorsvc.ingest_ransomware_alert(s, r) == gid


# ------------------------------------------------------------------ orgs & graph
def test_org_assets_share_watch_items_and_backfill_alerts():
    with session_scope() as s:
        o1 = orgsvc.create_org(s, "ACME Corp")
        o2 = orgsvc.create_org(s, "ACME Corp.")
        assert o2.slug != o1.slug
        with pytest.raises(orgsvc.OrgError):
            orgsvc.create_org(s, "ACME Corp")
        a1, created = orgsvc.add_asset(s, o1.id, "domain", "@ACME-corp.com")
        assert created and orgsvc.asset_dict(s, a1)["value"] == "acme-corp.com"
        assert orgsvc.add_asset(s, o1.id, "domain", "acme-corp.com")[1] is False
        with pytest.raises(orgsvc.OrgError):
            orgsvc.add_asset(s, o1.id, "brand", "ab")
        al = Alert(title="hit", severity="high", matches=[{"id": a1.watch_id, "kind": "domain", "value": "acme-corp.com"}])
        s.add(al)
        s.flush()
        assert orgsvc.link_alert(s, al) == {o1.id}
        a2, _ = orgsvc.add_asset(s, o2.id, "domain", "acme-corp.com")  # shared watch item + backfill
        assert a2.watch_id == a1.watch_id
        assert s.query(AlertOrg).filter_by(org_id=o2.id, alert_id=al.id).count() == 1
        assert orgsvc.remove_asset(s, o1.id, a1.id)
        assert s.get(orgsvc.WatchItem, a2.watch_id) is not None  # still used by o2
        g = build_graph(s, f"org:{o2.id}", depth=2)
        ids = {n["id"] for n in g["nodes"]}
        assert {f"org:{o2.id}", f"asset:{a2.watch_id}", f"alert:{al.id}"} <= ids
        assert any(e["relation"] == "monitors" for e in g["edges"])
        assert build_graph(s)["nodes"]  # overview from seeds


def test_org_api_keys():
    with session_scope() as s:
        o = orgsvc.create_org(s, "Tenant")
        k, raw = orgsvc.create_key(s, o.id, "ci")
        assert raw.startswith("dwk_") and k.key_hash != raw
        assert orgsvc.resolve_key(s, raw).org_id == o.id
        assert orgsvc.resolve_key(s, "dwk_wrong") is None and orgsvc.resolve_key(s, None) is None


def test_ransomware_alert_profiles_group_and_scores_known_actor():
    from darkweb_monitor.alerts.service import dedup_key, raise_alert
    with session_scope() as s:
        a, created = raise_alert(s, source="ransomware", key=dedup_key("r", "x"), severity="critical",
                                 title="Ransomware group 'Qilin' lists victim 'ACME'", description="victim")
        assert created and a.threat_class == "ransomware"
        assert any("known threat actor" in f["factor"] for f in a.risk_factors)
        actor = s.query(ThreatActor).filter_by(name="Qilin").one()
        assert actor.risk_score > 0 and actor.profile.get("built_at")


# ------------------------------------------------------------------ review regressions
def test_tenant_cannot_claim_watched_values_or_add_regex():
    with session_scope() as s:
        a = orgsvc.create_org(s, "Owner")
        b = orgsvc.create_org(s, "Intruder")
        orgsvc.add_asset(s, a.id, "domain", "acme-corp.com")
        with pytest.raises(orgsvc.OwnershipError):
            orgsvc.add_asset(s, b.id, "domain", "acme-corp.com", tenant=True)
        for t, v in (("regex", "(a+)+$"), ("keyword", "acme"), ("domain", "com"), ("domain", "%"),
                     ("domain", "co.uk")):
            with pytest.raises(orgsvc.OrgError):
                orgsvc.add_asset(s, b.id, t, v, tenant=True)
        assert orgsvc.like_escape("a_b%c") == r"a\_b\%c"


def test_custody_truncation_and_metadata_edits_are_detected():
    with session_scope() as s:
        _, a = _page_alert(s)
        ev = evsvc.capture_for_alert(s, a)
        evsvc.verify(s, ev)  # adds a 2nd entry
        assert evsvc.verify(s, ev, log=False)["ok"]
        last = s.query(CustodyEvent).filter_by(evidence_id=ev.id, seq=2).one()
        s.delete(last)
        s.flush()
        assert "truncated" in " ".join(evsvc.verify(s, ev, log=False)["problems"])
    with session_scope() as s:
        _, a = _page_alert(s, "other content")
        ev = evsvc.capture_for_alert(s, a)
        ev.alert_id = None  # re-point the evidence silently
        s.flush()
        assert "metadata" in " ".join(evsvc.verify(s, ev, log=False)["problems"])


def test_recrawl_does_not_inflate_actor_mentions():
    with session_scope() as s:
        _, a = _page_alert(s)
        for _ in range(3):
            actorsvc.ingest_forum_posts(s, parse_forum(PHPBB), host="f.onion", page_id=a.page_id,
                                        watch_terms=["acme-corp.com"], alert_id=a.id)
        assert s.query(ThreatActor).filter_by(name="dark_seller").one().mention_count == 1


def test_failing_enrichment_step_does_not_lose_the_alert(monkeypatch):
    from darkweb_monitor.alerts.service import dedup_key, raise_alert
    from darkweb_monitor.intel import orgs as orgs_mod

    def boom(s, alert):
        s.add(AlertOrg(alert_id=alert.id, org_id=999999))  # FK violation inside the step
        s.flush()
    monkeypatch.setattr(orgs_mod, "link_alert", boom)
    with session_scope() as s:
        raise_alert(s, source="crawler", key=dedup_key("x"), title="LockBit ransom note", description="",
                    severity="high")
    with session_scope() as s:
        a = s.query(Alert).one()
        assert a.threat_class == "ransomware" and a.risk_score > 0
