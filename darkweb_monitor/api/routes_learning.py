"""API: feedback, lessons, suppression rules, term quality, regression cases, evaluation."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from config.settings import DATA_DIR
from ..storage.db import audit, session_scope
from ..storage.models import Alert, EvalCase, Lesson, Page, SuppressionRule, utcnow
from .routes import require_key

router = APIRouter(dependencies=[Depends(require_key)])
Label = Literal["true_positive", "false_positive", "benign", "needs_more_info"]
Sev = Literal["low", "medium", "high", "critical"]


class FeedbackIn(BaseModel):
    agree: Optional[bool] = None
    label: Optional[Label] = None
    severity: Optional[Sev] = None
    comment: str = Field(default="", max_length=4000)
    create_lesson: bool = False
    lesson_title: str = Field(default="", max_length=300)
    add_to_eval: Optional[bool] = None
    set_status: Optional[Literal["acknowledged", "resolved", "false_positive"]] = None


class LessonIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    text: str = Field(min_length=5, max_length=2000)
    verdict: Optional[Label] = None
    severity: Optional[Sev] = None
    terms: list[str] = []
    status: Literal["active", "proposed", "disabled"] = "active"


class LessonPatch(BaseModel):
    title: Optional[str] = None
    text: Optional[str] = None
    verdict: Optional[str] = None
    severity: Optional[str] = None
    terms: Optional[list[str]] = None
    status: Optional[Literal["active", "proposed", "disabled"]] = None


class RuleIn(BaseModel):
    watch_kind: str = "keyword"
    watch_value: str = Field(min_length=1, max_length=512)
    context_keywords: list[str] = []
    host: str = ""
    action: Literal["downgrade", "suppress"] = "downgrade"
    severity: Sev = "low"
    reason: str = ""
    status: Literal["active", "proposed", "disabled"] = "active"


class RulePatch(BaseModel):
    context_keywords: Optional[list[str]] = None
    host: Optional[str] = None
    action: Optional[Literal["downgrade", "suppress"]] = None
    severity: Optional[Sev] = None
    status: Optional[Literal["active", "proposed", "disabled"]] = None


# ------------------------------------------------------------------ overview
@router.get("/learning/summary")
def summary():
    from ..learning.feedback import stats
    with session_scope() as s:
        lessons = {st: s.query(Lesson).filter_by(status=st).count() for st in ("active", "proposed", "disabled")}
        rules = {st: s.query(SuppressionRule).filter_by(status=st).count() for st in ("active", "proposed", "disabled")}
        cases = s.query(EvalCase).filter_by(active=True).count()
    return {"feedback": stats(), "lessons": lessons, "rules": rules, "eval_cases": cases, "eval": _eval_state()}


# ------------------------------------------------------------------ feedback
@router.post("/alerts/{aid}/feedback", status_code=201)
def give_feedback(aid: int, b: FeedbackIn):
    from ..learning.feedback import record
    try:
        res = record(aid, agree=b.agree, label=b.label or "", severity=b.severity or "", comment=b.comment,
                     create_lesson=b.create_lesson, lesson_title=b.lesson_title, add_to_eval=b.add_to_eval, actor="api")
    except KeyError as e:
        raise HTTPException(404, "alert not found") from e
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    if b.set_status:
        with session_scope() as s:
            s.get(Alert, aid).status = b.set_status
    return res


# ------------------------------------------------------------------ lessons
@router.get("/lessons")
def list_lessons(status: Optional[str] = None):
    from ..learning.lessons import to_dict
    with session_scope() as s:
        q = s.query(Lesson).order_by(Lesson.id.desc())
        if status:
            q = q.filter(Lesson.status.in_(status.split(",")))
        return [to_dict(lesson) for lesson in q]


@router.post("/lessons", status_code=201)
def add_lesson(b: LessonIn):
    with session_scope() as s:
        lesson = Lesson(title=b.title, text=b.text, verdict=b.verdict or "", severity=b.severity or "",
                        terms=b.terms[:10], source="manual", status=b.status)
        s.add(lesson)
        s.flush()
        lid = lesson.id
    audit("lesson.add", b.title, actor="api")
    return {"id": lid}


@router.patch("/lessons/{lid}")
def patch_lesson(lid: int, b: LessonPatch):
    with session_scope() as s:
        lesson = s.get(Lesson, lid)
        if not lesson:
            raise HTTPException(404, "not found")
        for k, v in b.model_dump(exclude_unset=True).items():
            setattr(lesson, k, v)
    audit("lesson.update", f"{lid} {b.model_dump(exclude_unset=True)}", actor="api")
    return {"ok": True}


@router.delete("/lessons/{lid}")
def delete_lesson(lid: int):
    with session_scope() as s:
        lesson = s.get(Lesson, lid)
        if not lesson:
            raise HTTPException(404, "not found")
        s.delete(lesson)
    return {"ok": True}


@router.post("/lessons/search")
def search_lessons(b: dict):
    from ..learning.lessons import retrieve
    return [{"score": sc, **lesson} for sc, lesson in retrieve(str(b.get("query", "")), b.get("terms") or [], k=8, min_score=0.3)]


@router.post("/alerts/{aid}/draft-lesson", status_code=201)
def draft_lesson(aid: int, b: FeedbackIn):
    """Let the local AI generalise a corrected case into a lesson - saved as 'proposed'."""
    from ..ai.base import AIError
    from ..ai.router import get_router
    with session_scope() as s:
        a = s.get(Alert, aid)
        if not a:
            raise HTTPException(404, "alert not found")
        ctx = "; ".join((m.get("context") or "") for m in (a.matches or [])[:3])
        if not ctx and a.page_id:
            p = s.get(Page, a.page_id)
            ctx = (p.ai_summary or "") if p else ""
        ai_v = ((a.triage or {}).get("analyst") or {}).get("verdict", "")
        title, matches = a.title, a.matches or []
    try:
        d = get_router().draft_lesson(title, matches, ai_v, b.label or "", b.comment, ctx)
    except AIError as e:
        raise HTTPException(503, f"no local AI available to draft a lesson: {e}") from e
    with session_scope() as s:
        lesson = Lesson(title=d["title"], text=d["text"], terms=d["terms"], verdict=b.label or "",
                        severity=b.severity or "", source="ai_draft", status="proposed", source_alert_id=aid,
                        example=ctx[:500])
        s.add(lesson)
        s.flush()
        return {"id": lesson.id, **d, "status": "proposed"}


# ------------------------------------------------------------------ rules & term quality
@router.get("/learning/terms")
def terms():
    from ..learning.rules import term_stats
    return term_stats()


@router.get("/rules")
def list_rules(status: Optional[str] = None):
    from ..learning.rules import to_dict
    with session_scope() as s:
        q = s.query(SuppressionRule).order_by(SuppressionRule.id.desc())
        if status:
            q = q.filter(SuppressionRule.status.in_(status.split(",")))
        return [to_dict(r) for r in q]


@router.post("/rules", status_code=201)
def add_rule(b: RuleIn):
    if not b.context_keywords and not b.host:
        raise HTTPException(422, "a rule needs context keywords or a host")
    with session_scope() as s:
        r = SuppressionRule(**b.model_dump(), created_by="user")
        s.add(r)
        s.flush()
        rid = r.id
    audit("rule.add", f"{b.watch_value} {b.context_keywords} {b.action}", actor="api")
    return {"id": rid}


@router.patch("/rules/{rid}")
def patch_rule(rid: int, b: RulePatch):
    with session_scope() as s:
        r = s.get(SuppressionRule, rid)
        if not r:
            raise HTTPException(404, "not found")
        for k, v in b.model_dump(exclude_unset=True).items():
            setattr(r, k, v)
    audit("rule.update", f"{rid} {b.model_dump(exclude_unset=True)}", actor="api")
    return {"ok": True}


@router.delete("/rules/{rid}")
def delete_rule(rid: int):
    with session_scope() as s:
        r = s.get(SuppressionRule, rid)
        if not r:
            raise HTTPException(404, "not found")
        s.delete(r)
    return {"ok": True}


@router.post("/rules/propose")
def propose_rules():
    from ..learning.rules import propose
    return {"created": propose()}


# ------------------------------------------------------------------ regression cases & eval
@router.get("/eval/cases")
def eval_cases():
    with session_scope() as s:
        return [{"id": c.id, "name": c.name, "expected": c.expected, "note": c.note, "active": c.active,
                 "source_alert_id": c.source_alert_id, "created_at": c.created_at.isoformat() + "Z"}
                for c in s.query(EvalCase).order_by(EvalCase.id.desc())]


@router.patch("/eval/cases/{cid}")
def toggle_case(cid: int, b: dict):
    with session_scope() as s:
        c = s.get(EvalCase, cid)
        if not c:
            raise HTTPException(404, "not found")
        if "active" in b:
            c.active = bool(b["active"])
        if "expected" in b and isinstance(b["expected"], list):
            c.expected = [str(x) for x in b["expected"]][:4]
    return {"ok": True}


@router.delete("/eval/cases/{cid}")
def delete_case(cid: int):
    with session_scope() as s:
        c = s.get(EvalCase, cid)
        if not c:
            raise HTTPException(404, "not found")
        s.delete(c)
    return {"ok": True}


_EVAL_FILE = DATA_DIR / "eval_last.json"
_eval_lock = threading.Lock()


def _eval_state() -> dict:
    try:
        return json.loads(_EVAL_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "never"}


@router.post("/eval/run", status_code=202)
def run_eval(provider: str = "auto"):
    """Runs analyst-eval in a separate process (the eval swaps databases)."""
    if _eval_state().get("status") == "running":
        raise HTTPException(409, "an evaluation is already running")
    cmd = ([sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "darkweb_monitor.cli"]) + \
          ["analyst-eval", "--provider", provider, "--json"]

    def work():
        with _eval_lock:
            _EVAL_FILE.write_text(json.dumps({"status": "running", "started": utcnow().isoformat() + "Z",
                                              "provider": provider}), encoding="utf-8")
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
                out = p.stdout[p.stdout.find("{"):] if "{" in p.stdout else ""
                res = json.loads(out) if out else {"error": (p.stderr or "no output")[-800:]}
                res.update(status="done", finished=utcnow().isoformat() + "Z", provider=provider)
            except Exception as e:  # noqa: BLE001
                res = {"status": "failed", "error": str(e)[:800], "provider": provider}
            _EVAL_FILE.write_text(json.dumps(res), encoding="utf-8")
    threading.Thread(target=work, daemon=True).start()
    audit("eval.run", provider, actor="api")
    return {"queued": True}
