"""Lesson library with lexical retrieval (works offline, no embedding model)."""
from __future__ import annotations

import math
import re
from collections import Counter

from ..storage.db import session_scope
from ..storage.models import Lesson

_TOKEN = re.compile(r"[a-z0-9@._-]{3,}")
STOP = set("""the and for with that this from are was were has have had not but you your our their its into about
over under than then them they there here what when where which while who whom why how all any can could should would
will just also only very more most some such other http https www com onion page post thread forum
der die das und ist ein eine nicht mit von bir ve ile bu için""".split())


def tokens(text: str) -> list[str]:
    return [t.strip("._-") for t in _TOKEN.findall((text or "").lower()) if t.strip("._-") not in STOP]


def _doc(lesson: Lesson) -> list[str]:
    return tokens(" ".join([lesson.title or "", lesson.text or "", lesson.example or "", " ".join(lesson.terms or [])]))


def retrieve(query: str, terms: list[str] | None = None, category: str = "", k: int = 4,
             min_score: float = 1.5) -> list[tuple[float, dict]]:
    """Score active lessons: shared watch terms dominate, then BM25-like token overlap."""
    terms_l = {t.lower() for t in (terms or []) if t}
    q = Counter(tokens(query))
    with session_scope() as s:
        lessons = s.query(Lesson).filter_by(status="active").all()
        if not lessons:
            return []
        docs = [(lesson, _doc(lesson)) for lesson in lessons]
        n = len(docs)
        df = Counter(t for _, d in docs for t in set(d))
        avg = sum(len(d) for _, d in docs) / n or 1
        scored = []
        for lesson, d in docs:
            tf = Counter(d)
            score = 0.0
            for t in q:
                if t in tf:
                    idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
                    score += idf * (tf[t] * 2.2) / (tf[t] + 1.2 * (0.25 + 0.75 * len(d) / avg))
            shared = terms_l & {t.lower() for t in (lesson.terms or [])}
            score += 4.0 * len(shared)
            if category and lesson.category and lesson.category == category:
                score += 0.5
            # lessons humans found unhelpful sink, helpful ones rise
            score *= 1 + 0.1 * min(lesson.helpful, 10) - 0.15 * min(lesson.unhelpful, 5)
            if score >= min_score:
                scored.append((round(score, 2), to_dict(lesson)))
        return sorted(scored, key=lambda x: -x[0])[:k]


def to_dict(lesson: Lesson) -> dict:
    return {"id": lesson.id, "title": lesson.title, "text": lesson.text, "verdict": lesson.verdict,
            "severity": lesson.severity, "terms": lesson.terms or [], "category": lesson.category,
            "example": lesson.example, "source": lesson.source, "status": lesson.status,
            "source_alert_id": lesson.source_alert_id, "uses": lesson.uses, "helpful": lesson.helpful,
            "unhelpful": lesson.unhelpful,
            "created_at": lesson.created_at.isoformat() + "Z" if lesson.created_at else None}


def format_for_prompt(items: list[tuple[float, dict]], max_chars: int = 1500) -> str:
    if not items:
        return ""
    lines = ["Lessons from earlier decisions of the human analysts (trusted guidance; still weigh the evidence):"]
    for _, lesson in items:
        v = f" [usual verdict: {lesson['verdict']}]" if lesson["verdict"] else ""
        lines.append(f"- Lesson #{lesson['id']}: {lesson['title']}{v} - {lesson['text']}")
    out = "\n".join(lines)
    return out[:max_chars]


def mark_used(ids: list[int]) -> None:
    if not ids:
        return
    with session_scope() as s:
        for lesson in s.query(Lesson).filter(Lesson.id.in_(ids)):
            lesson.uses = (lesson.uses or 0) + 1


def for_alert(alert: dict, k: int = 4) -> list[tuple[float, dict]]:
    terms = [m.get("value", "") for m in alert.get("matches") or []]
    query = " ".join([alert.get("title", ""), alert.get("description", "")[:600],
                      " ".join((m.get("context") or "") for m in alert.get("matches") or [])])
    return retrieve(query, terms, alert.get("category", ""), k)
