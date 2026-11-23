from fastapi.testclient import TestClient

from darkweb_monitor.analyst import service
from darkweb_monitor.analyst.agent import RulesAdapter
from darkweb_monitor.api.main import app
from darkweb_monitor.harness.session import SessionLog
from darkweb_monitor.learning import feedback, lessons, rules
from darkweb_monitor.pipeline import run_crawl
from darkweb_monitor.storage.db import session_scope
from darkweb_monitor.storage.models import (
    AgentSession, Alert, EvalCase, Feedback, Lesson, Page, SuppressionRule, WatchItem,
)
from conftest import ONION_A, FakeClient

BOOK = "phoenix"


def book_alert(i, status="new", text="discussing the phoenix novel in our book club"):
    with session_scope() as s:
        p = Page(url=f"http://{ONION_A}/b{i}", title=f"Book club {i}", content=text)
        s.add(p)
        s.flush()
        a = Alert(title=f"Watchlist hit [{BOOK}] on Book club {i}", severity="medium", page_id=p.id, url=p.url,
                  status=status, source="crawler",
                  matches=[{"kind": "keyword", "value": BOOK, "severity": "medium", "context": text}],
                  triage={"analyst": {"verdict": "true_positive", "session_id": None}})
        s.add(a)
        s.flush()
        return a.id


def run_analyst(aid):
    service.set_adapter(RulesAdapter())
    try:
        sid = service.start(aid)
        service._pool.submit(lambda: None).result(timeout=10)
    finally:
        service.set_adapter(None)
    return sid


def test_disagreement_creates_lesson_and_regression_case():
    with session_scope() as s:
        s.add(WatchItem(kind="keyword", value=BOOK, severity="medium"))
    aid = book_alert(1)
    res = feedback.record(aid, agree=False, label="false_positive", comment="Phoenix is a novel title in book-club "
                          "and literature threads - not our project.", create_lesson=True)
    assert res["ai_verdict"] == "true_positive" and res["agree"] is False
    with session_scope() as s:
        lesson = s.get(Lesson, res["lesson_id"])
        assert lesson.status == "active" and lesson.verdict == "false_positive" and BOOK in lesson.terms
        case = s.get(EvalCase, res["eval_case_id"])
        assert case.expected[0] == "false_positive" and "book club" in case.page_content
    st = feedback.stats()
    assert st["judged"] == 1 and st["agreement"] == 0.0


def test_lessons_are_retrieved_into_investigations_and_get_credit():
    with session_scope() as s:
        s.add(Lesson(title="Phoenix in literature threads is noise", text="Book or film discussion of Phoenix is not "
                     "about our project.", verdict="false_positive", severity="low", terms=[BOOK], status="active"))
        s.add(Lesson(title="Unrelated", text="Ransomware posts naming our domain are critical.", verdict="true_positive",
                     terms=["acme.com"], status="active"))
        s.add(Lesson(title="Draft", text="phoenix something", terms=[BOOK], status="proposed"))
    aid = book_alert(2)
    hits = lessons.for_alert({"title": "Watchlist hit [phoenix] on Book club 2",
                              "matches": [{"kind": "keyword", "value": BOOK, "context": "phoenix novel book club"}]})
    assert [h[1]["title"] for h in hits][0] == "Phoenix in literature threads is noise"
    assert all(h[1]["status"] == "active" for h in hits)       # proposed lessons are never used
    sid = run_analyst(aid)
    ev = SessionLog(sid).events()
    first_user = next(e for e in ev if e.type == "user/message").payload["content"]
    assert "Lesson #" in first_user and "Phoenix in literature" in first_user
    assert any(e.type == "lessons/used" for e in ev)
    with session_scope() as s:
        rep = s.get(AgentSession, sid).report
        assert rep["verdict"] == "false_positive"                 # rule-based analyst followed the lesson
        assert any("lesson" in e["source"] for e in rep["evidence"])
    feedback.record(aid, agree=True)
    with session_scope() as s:
        lsn = s.query(Lesson).filter_by(title="Phoenix in literature threads is noise").one()
        assert lsn.uses == 1 and lsn.helpful == 1


def test_term_stats_rule_proposal_and_pipeline_suppression(site):
    with session_scope() as s:
        s.add(WatchItem(kind="keyword", value=BOOK, severity="medium"))
    ids = [book_alert(i, text=f"phoenix novel chapter {i} book club review") for i in range(4)]
    for aid in ids[:3]:
        feedback.record_status(aid, "false_positive")
    stats = {t["value"]: t for t in rules.term_stats()}
    assert stats[BOOK]["fp"] == 3 and stats[BOOK]["noisy"]
    created = rules.propose()
    assert len(created) == 1
    with session_scope() as s:
        r = s.get(SuppressionRule, created[0])
        assert r.status == "proposed" and set(r.context_keywords) & {"novel", "book", "club", "review"}
        assert BOOK not in r.context_keywords
    assert rules.propose() == []                                 # no duplicate proposals
    # proposed rules do nothing until approved
    site[f"http://{ONION_A}/thread/2"] = "<html><title>Chat</title><body>the phoenix novel book club meets</body></html>"
    run_crawl(f"http://{ONION_A}/", depth=2, spider_client=FakeClient(site))
    with session_scope() as s:
        before = s.query(Alert).filter(Alert.url.like("%thread/2")).one()
        assert before.severity == "medium"
        s.get(SuppressionRule, created[0]).status = "active"
        s.get(SuppressionRule, created[0]).action = "suppress"
    site[f"http://{ONION_A}/thread/2"] += " updated"
    site[f"http://{ONION_A}/thread/3"] = "<html><title>Lit</title><body>phoenix novel discussion</body></html>"
    site[f"http://{ONION_A}/"] = site[f"http://{ONION_A}/"].replace("</body>", '<a href="/thread/3">lit</a></body>')
    run_crawl(f"http://{ONION_A}/", depth=2, spider_client=FakeClient(site))
    with session_scope() as s:
        assert s.query(Alert).filter(Alert.url.like("%thread/3")).count() == 0   # suppressed
        assert s.get(SuppressionRule, created[0]).hits >= 1


def test_downgrade_rule_keeps_alert_but_lowers_severity():
    with session_scope() as s:
        s.add(SuppressionRule(watch_kind="keyword", watch_value=BOOK, context_keywords=["novel"], action="downgrade",
                              severity="low", status="active"))
    m, applied = rules.apply([{"kind": "keyword", "value": "Phoenix", "severity": "high"}], "a phoenix NOVEL", "http://x/")
    assert m[0]["severity"] == "low" and applied[0]["action"] == "downgrade"
    m, applied = rules.apply([{"kind": "keyword", "value": BOOK, "severity": "high"}], "phoenix vpn creds", "")
    assert m[0]["severity"] == "high" and not applied


def test_eval_includes_corrected_cases_and_lessons_make_them_pass():
    from darkweb_monitor.analyst.evals import run
    aid = book_alert(9)
    feedback.record(aid, agree=False, label="false_positive", comment="literature, not our project")
    before = run("rules")
    case = next(r for r in before["results"] if r["scenario"].startswith("case-"))
    assert case["verdict"] == "needs_more_info"                   # unsure before learning
    with session_scope() as s:
        s.add(Lesson(title="Phoenix book discussions are noise", text="Phoenix in book clubs is literature.",
                     verdict="false_positive", terms=[BOOK], status="active"))
    after = run("rules")
    case = next(r for r in after["results"] if r["scenario"].startswith("case-"))
    assert case["pass"] and case["verdict"] == "false_positive" and after["lessons"] == 1  # learned from the lesson


def test_learning_api():
    aid = book_alert(5)
    with TestClient(app) as c:
        r = c.post(f"/api/alerts/{aid}/feedback", json={"agree": False, "label": "false_positive",
                                                        "comment": "noise", "create_lesson": True,
                                                        "set_status": "false_positive"})
        assert r.status_code == 201 and r.json()["lesson_id"]
        assert c.get(f"/api/alerts/{aid}").json()["status"] == "false_positive"
        summ = c.get("/api/learning/summary").json()
        assert summ["lessons"]["active"] == 1 and summ["eval_cases"] == 1 and summ["feedback"]["agreement"] == 0.0
        lid = c.post("/api/lessons", json={"title": "Manual lesson", "text": "Some text here", "terms": ["x"]}).json()["id"]
        assert c.patch(f"/api/lessons/{lid}", json={"status": "disabled"}).status_code == 200
        assert {x["status"] for x in c.get("/api/lessons").json()} == {"active", "disabled"}
        assert c.post("/api/rules", json={"watch_value": BOOK}).status_code == 422
        rid = c.post("/api/rules", json={"watch_value": BOOK, "context_keywords": ["novel"]}).json()["id"]
        assert c.patch(f"/api/rules/{rid}", json={"status": "disabled"}).status_code == 200
        assert c.get("/api/learning/terms").status_code == 200
        assert c.get("/api/eval/cases").json()[0]["expected"][0] == "false_positive"
        assert c.post(f"/api/alerts/{aid}/draft-lesson", json={"label": "false_positive"}).status_code == 503  # no AI
        # status change via the normal alert API is an implicit label
        aid2 = book_alert(6)
        c.patch(f"/api/alerts/{aid2}", json={"status": "resolved"})
        with session_scope() as s:
            fb = s.query(Feedback).filter_by(alert_id=aid2).one()
            assert fb.source == "status" and fb.label == "true_positive"
