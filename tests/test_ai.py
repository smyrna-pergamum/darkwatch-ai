import pytest

from config.settings import settings
from darkweb_monitor.ai.agent import AgentFrontier
from darkweb_monitor.ai.base import AIError, parse_json, redact
from darkweb_monitor.ai.router import AIRouter
from conftest import FakeProvider, Unavailable


def test_raw_content_never_goes_to_cloud_by_default():
    cloud = FakeProvider("cloud", lambda p: {"summary": "x"})
    r = AIRouter(local=Unavailable("ollama"), cloud=cloud)
    assert r.providers_for("page") == []
    with pytest.raises(AIError):
        r.analyze_page("u", "t", "secret page text")
    assert cloud.prompts == []
    # derived tasks may use the cloud
    assert r.providers_for("run_summary") == [cloud]


def test_cloud_raw_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "CLOUD_ALLOW_RAW", True)
    cloud = FakeProvider("cloud", lambda p: {"summary": "s", "severity": "HIGH", "category": "leak_site"})
    r = AIRouter(local=Unavailable("ollama"), cloud=cloud)
    res = r.analyze_page("u", "t", "mail bob@corp.com")
    assert res["severity"] == "high"
    assert "bob@corp.com" not in cloud.prompts[0]  # redacted


def test_fallback_between_providers():
    cloud = FakeProvider("cloud", lambda p: AIError("boom"))
    local = FakeProvider("ollama", lambda p: {"summary": "ok", "risk_level": "medium"})
    r = AIRouter(local=local, cloud=cloud)
    out = r.summarize_run("u", [{"url": "u", "summary": "s", "severity": "low"}], 0, 0)
    assert out["summary"] == "ok" and out["risk_level"] == "medium"
    assert len(cloud.prompts) == 1 and len(local.prompts) == 1


def test_parse_json_tolerant():
    assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json('Sure! {"a": 2} hope this helps') == {"a": 2}
    with pytest.raises(AIError):
        parse_json("no json")
    assert "[EMAIL]" in redact("x@y.com") and "[REDACTED]" in redact("password: hunter2")


def test_link_scoring_maps_indices():
    local = FakeProvider("ollama", lambda p: {"scores": [{"i": 1, "score": 9}, {"i": 7, "score": 3}]})
    r = AIRouter(local=local, cloud=Unavailable("cloud"))
    out = r.score_links([{"url": "a", "text": ""}, {"url": "b", "text": ""}], ["acme"])
    assert out == {"b": 9.0}


def test_agent_frontier_follows_ai_and_stops():
    decisions = iter([{"action": "visit", "index": 1, "reason": "dump", "note": "found dump"},
                      {"action": "stop", "reason": "goal reached"}])
    local = FakeProvider("ollama", lambda p: next(decisions))
    r = AIRouter(local=local, cloud=Unavailable("cloud"))
    f = AgentFrontier(r, "find acme", ["acme"], max_steps=5)
    f.push("http://s/", 0)
    assert f.pop() == ("http://s/", 0)
    f.push("http://s/chat", 1, "general chat")
    f.push("http://s/acme-dump", 1, "acme dump")
    f.push("http://s/login", 1, "login")  # forbidden, never offered
    f.observe({"url": "http://s/", "analysis": {"summary": "forum"}})
    url, _ = f.pop()
    # candidates are ranked by heuristic first: acme-dump is index 0, chat index 1
    assert url == "http://s/chat"
    assert f.pop() is None and "goal reached" in f.stop_reason()
    assert f.notes == ["found dump"]
    assert all("login" not in (e.get("url") or "") for e in f.log)


def test_agent_frontier_heuristic_fallback():
    r = AIRouter(local=Unavailable("ollama"), cloud=Unavailable("cloud"))
    f = AgentFrontier(r, "find leaks", [], max_steps=1)
    f.push("http://s/", 0)
    f.pop()
    f.push("http://s/rules", 1, "forum rules")
    f.push("http://s/leaks", 1, "new leaks")
    assert f.pop()[0] == "http://s/leaks"
    assert f.log[-1]["by"] == "heuristic"
    assert f.pop() is None and "budget" in f.stop_reason()
