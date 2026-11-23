import json

from config.settings import settings
from darkweb_monitor.ai import router as router_mod
from darkweb_monitor.ai.router import AIRouter
from darkweb_monitor.pipeline import run_crawl
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import Alert, CrawlRun, Indicator, Page, Target, Task, WatchItem
from conftest import ONION_A, FakeClient, FakeProvider, Unavailable

START = f"http://{ONION_A}/"


def add_watch(kind, value, sev="high"):
    with session_scope() as s:
        s.add(WatchItem(kind=kind, value=value, severity=sev))


def test_standard_crawl_alerts_iocs_and_dedup(site):
    add_watch("domain", "acme-corp.com")
    client = FakeClient(site)
    res = run_crawl(START, depth=2, spider_client=client)
    assert res["status"] == "done", res["error"]
    assert res["pages_crawled"] == 4 and res["alerts_raised"] == 1
    with session_scope() as s:
        a = s.query(Alert).one()
        assert a.severity == "high" and a.source == "crawler" and a.matches[0]["value"] == "acme-corp.com"
        page = s.get(Page, a.page_id)
        assert "hunter22" not in page.content  # credentials masked before storage
        vals = {(i.ioc_type, i.value) for i in s.query(Indicator)}
        assert ("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") in vals
        assert any(t == "credential" for t, _ in vals)
        assert s.query(Indicator).filter_by(ioc_type="email", value="admin@acme-corp.com").one().on_watchlist
        run = s.query(CrawlRun).one()
        summ = json.loads(run.ai_summary)
        assert summ["provider"] == "rules" and summ["risk_level"] == "high"
        assert s.query(Target).one().last_status == "up"
    # second run: same content -> no duplicate alert, pages unchanged
    res2 = run_crawl(START, depth=2, spider_client=FakeClient(site))
    assert res2["alerts_raised"] == 0 and res2["pages_changed"] == 0
    with session_scope() as s:
        assert s.query(Alert).count() == 1
        assert s.query(Page).count() == 4


def test_changed_content_reoccurs_on_same_alert(site):
    add_watch("domain", "acme-corp.com")
    run_crawl(START, depth=2, spider_client=FakeClient(site))
    site[f"http://{ONION_A}/thread/1"] += " <p>update: more acme-corp.com data</p>"
    res = run_crawl(START, depth=2, spider_client=FakeClient(site))
    assert res["pages_changed"] == 1 and res["alerts_raised"] == 0
    with session_scope() as s:
        assert s.query(Alert).one().occurrences == 2


def test_resolved_alert_reopens_false_positive_stays_quiet(site):
    add_watch("domain", "acme-corp.com")
    run_crawl(START, depth=2, spider_client=FakeClient(site))
    with session_scope() as s:
        s.query(Alert).one().status = "false_positive"
    site[f"http://{ONION_A}/thread/1"] += " changed"
    run_crawl(START, depth=2, spider_client=FakeClient(site))
    with session_scope() as s:
        assert s.query(Alert).count() == 1
        s.query(Alert).one().status = "resolved"
    site[f"http://{ONION_A}/thread/1"] += " again"
    run_crawl(START, depth=2, spider_client=FakeClient(site))
    with session_scope() as s:
        assert s.query(Alert).count() == 2


def test_safety_block_discards_page(site):
    site[f"http://{ONION_A}/thread/2"] = "<html><title>x</title><body>cp links</body></html>"
    res = run_crawl(START, depth=2, spider_client=FakeClient(site))
    with session_scope() as s:
        urls = {p.url for p in s.query(Page)}
    assert f"http://{ONION_A}/thread/2" not in urls
    assert res["pages_crawled"] < 4


def test_tor_required_blocks_run(site, monkeypatch):
    monkeypatch.setattr(settings, "TOR_REQUIRED", True)
    client = FakeClient(site)
    res = run_crawl(START, spider_client=client)
    assert res["status"] == "failed" and "TOR" in res["error"]
    assert client.calls == []


def test_ai_page_analysis_and_hallucination_guard(site):
    def handler(prompt):
        if "Analyse this page" in prompt:
            sev = "critical" if "Selling" in prompt else "low"
            return {"summary": "AI summary", "severity": sev, "category": "leak_site",
                    "iocs": [{"type": "domain", "value": "acme-corp.com", "confidence": 0.9},
                             {"type": "ip", "value": "1.1.1.1", "confidence": 0.9}]}
        if "follow-up monitoring tasks" in prompt:
            return {"tasks": [{"kind": "recrawl", "title": "again", "payload": {"in_minutes": 30}},
                              {"kind": "add_target", "title": "t", "payload": {"url": "http://" + "c" * 56 + ".onion/"}}]}
        if "post-crawl assessment" in prompt:
            return {"summary": "run", "risk_level": "critical"}
        if "Triage" in prompt:
            return {"true_positive": True, "confidence": 0.9, "reason": "real", "severity": "critical"}
        return {}
    local = FakeProvider("ollama", handler)
    router_mod.set_router(AIRouter(local=local, cloud=Unavailable("cloud")))
    res = run_crawl(START, depth=2, spider_client=FakeClient(site))
    assert res["alerts_raised"] == 1
    with session_scope() as s:
        a = s.query(Alert).one()
        assert a.severity == "critical" and a.triage["reason"] == "real"
        vals = {i.value for i in s.query(Indicator).filter(Indicator.ioc_type.like("ai:%"))}
        assert "acme-corp.com" in vals and "1.1.1.1" not in vals  # not in page text -> dropped
        tasks = {t.kind: t for t in s.query(Task)}
        assert tasks["recrawl"].status == "approved"      # auto-approved kind
        assert tasks["add_target"].status == "proposed"   # never auto
    assert res["ai_summary"]["summary"] == "run"


def test_smart_mode_prioritises(site):
    add_watch("brand", "ACME")
    site[f"http://{ONION_A}/"] = site[f"http://{ONION_A}/"].replace(
        '<a href="/thread/1">Database dump ACME corp</a>', "").replace("</body>", '<a href="/thread/1">Database dump ACME corp</a></body>')
    client = FakeClient(site)
    run_crawl(START, depth=1, max_pages=2, mode="smart", spider_client=client)
    assert client.calls[1] == f"http://{ONION_A}/thread/1"  # last link on the page, but most relevant


def test_agent_mode_records_decisions(site):
    decisions = iter([{"action": "visit", "index": 0, "reason": "dump thread", "note": "acme dump"},
                      {"action": "stop", "reason": "enough"}])

    from darkweb_monitor.ai.base import AIError
    local = FakeProvider("ollama", lambda p: next(decisions) if "steering" in p else AIError("n/a"))
    router_mod.set_router(AIRouter(local=local, cloud=Unavailable("cloud")))
    res = run_crawl(START, depth=2, mode="agent", goal="find acme", spider_client=FakeClient(site))
    with session_scope() as s:
        run = s.get(CrawlRun, res["run_id"])
        assert [e["action"] for e in run.agent_log] == ["visit", "visit", "stop"]
        assert run.mode == "agent"
    assert "enough" in res["ai_summary"]["stop_reason"]
