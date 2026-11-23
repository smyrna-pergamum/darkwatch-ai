from datetime import timedelta

from darkweb_monitor.sources import runner as src_runner
from darkweb_monitor.sources.base import Finding, Source
from darkweb_monitor.sources.hibp import HIBPSource
from darkweb_monitor.sources.ransomware import RansomwareLiveSource
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import Alert, Target, Task, WatchItem, utcnow
from darkweb_monitor.tasks import _clean, create_task, heuristic_plan, run_due_tasks
from darkweb_monitor.watchlist import WatchTerm
from config.settings import settings


def test_clean_rejects_bad_payloads():
    assert _clean({"kind": "rm -rf"}, 1, 1) is None
    assert _clean({"kind": "add_target", "payload": {"url": "http://google.com"}}, 1, 1) is None
    assert _clean({"kind": "add_watch", "payload": {"kind": "keyword", "value": "x"}}, 1, 1) is None
    c = _clean({"kind": "recrawl", "payload": {"in_minutes": 1}}, 1, 1)
    assert c["payload"]["in_minutes"] == 15  # clamped


def test_add_target_never_auto_approved(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_APPROVE_TASKS", "recrawl,add_target,add_watch")
    tid = create_task(_clean({"kind": "add_target", "payload": {"url": "http://" + "e" * 56 + ".onion"}}, None, None))
    wid = create_task(_clean({"kind": "add_watch", "payload": {"kind": "brand", "value": "Acme"}}, None, None))
    with session_scope() as s:
        assert s.get(Task, tid).status == "proposed"
        assert s.get(Task, wid).status == "done"
        assert s.query(WatchItem).filter_by(value="Acme").one().source == "ai"
    # duplicates are ignored
    assert create_task(_clean({"kind": "add_target", "payload": {"url": "http://" + "e" * 56 + ".onion"}}, None, None)) is None


def test_heuristic_plan_and_due_tasks():
    with session_scope() as s:
        s.add(Target(url="http://x.onion/"))
    plan = heuristic_plan({"target_id": 1, "alerts": [{"severity": "critical", "title": "t", "url": "u"}],
                           "discovered_from_hits": ["http://" + "f" * 56 + ".onion/"]})
    assert {t["kind"] for t in plan} == {"recrawl", "review", "add_target"}
    tid = create_task(_clean(plan[0], 1, None), source="rule")
    with session_scope() as s:
        t = s.get(Task, tid)
        assert t.status == "approved"
        t.due_at = utcnow() - timedelta(minutes=1)
    submitted = []
    assert run_due_tasks(lambda **kw: submitted.append(kw) or 99) == 1
    assert submitted == [{"target_id": 1, "trigger": "task"}]
    with session_scope() as s:
        assert s.get(Task, tid).status == "done"


def test_hibp_source(monkeypatch):
    monkeypatch.setattr(settings, "HIBP_API_KEY", "k")
    monkeypatch.setattr("time.sleep", lambda *_: None)
    calls = []

    def fake_get_json(self, s, url, **kw):
        calls.append(url)
        if "breachedaccount" in url:
            return [{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04",
                     "DataClasses": ["Email addresses", "Passwords"]}]
        if "breacheddomain" in url:
            return {"jane": ["Adobe"]}
        return {"Name": "Adobe", "Title": "Adobe", "DataClasses": ["Email addresses"]}
    monkeypatch.setattr(Source, "get_json", fake_get_json)
    f, q = HIBPSource().run([WatchTerm("email", "ceo@acme.com", "high"), WatchTerm("domain", "acme.com")])
    assert q == 2 and len(f) == 2
    assert f[0].severity == "high" and f[1].severity == "low"


def test_ransomware_source_filters_unrelated(monkeypatch):
    monkeypatch.setattr(settings, "RANSOMWARE_LIVE_ENABLED", True)
    monkeypatch.setattr(Source, "get_json", lambda self, s, url, **kw: [
        {"victim": "Acme Corp", "group": "lockbit3", "domain": "acme.com", "discovered": "2026-11-01"},
        {"victim": "Other Ltd", "group": "akira", "domain": "other.com"}])
    f, _ = RansomwareLiveSource().run([WatchTerm("domain", "acme.com", "high")])
    assert len(f) == 1 and f[0].severity == "critical" and "lockbit3" in f[0].title


def test_source_runner_creates_deduplicated_alerts(monkeypatch):
    class Dummy(Source):
        name, label = "dummy", "Dummy"

        def enabled(self):
            return True

        def run(self, terms):
            return [Finding(source="dummy", key="k1", title="found", description="d", severity="high",
                            matched=terms[0], indicators=[("email", "a@acme.com")],
                            discovered_onions=["http://" + "g" * 56 + ".onion/"])], 1
    monkeypatch.setattr(src_runner, "SOURCES", [Dummy()])
    with session_scope() as s:
        s.add(WatchItem(kind="domain", value="acme.com", severity="medium"))
    r1 = src_runner.run_source("dummy")
    r2 = src_runner.run_source("dummy")
    assert r1["alerts"] == 1 and r2["alerts"] == 0
    with session_scope() as s:
        a = s.query(Alert).one()
        assert a.source == "dummy" and a.occurrences == 2
        assert s.query(Task).filter_by(kind="add_target").count() == 1
