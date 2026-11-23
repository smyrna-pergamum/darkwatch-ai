"""Append-only session event log and the model-history projection."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field

from sqlalchemy import func

from ..storage.db import session_scope
from ..storage.models import AgentEvent, AgentSession, utcnow

# Event types that change what the model sees
MODEL_VISIBLE = {"user/message", "assistant/message", "tool/result", "approval/resolved"}

_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock(session_id: int) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(session_id, threading.Lock())


@dataclass
class Event:
    seq: int
    type: str
    payload: dict = field(default_factory=dict)
    ts: str = ""


class SessionLog:
    def __init__(self, session_id: int):
        self.session_id = session_id

    @classmethod
    def create(cls, agent: str, title: str = "", subject_type: str = "", subject_id: int | None = None,
               trigger: str = "manual") -> "SessionLog":
        with session_scope() as s:
            row = AgentSession(agent=agent, title=title[:500], subject_type=subject_type,
                               subject_id=subject_id, trigger=trigger, status="idle")
            s.add(row)
            s.flush()
            sid = row.id
        log = cls(sid)
        log.append("session/created", {"agent": agent, "subject_type": subject_type,
                                       "subject_id": subject_id, "trigger": trigger})
        return log

    def append(self, type_: str, payload: dict | None = None) -> int:
        payload = json.loads(json.dumps(payload or {}, default=str))  # lossless JSON snapshot
        with _lock(self.session_id), session_scope() as s:
            seq = (s.query(func.max(AgentEvent.seq)).filter_by(session_id=self.session_id).scalar() or 0) + 1
            s.add(AgentEvent(session_id=self.session_id, seq=seq, type=type_, payload=payload))
            row = s.get(AgentSession, self.session_id)
            if row:
                row.updated_at = utcnow()
        return seq

    def events(self, since: int = 0) -> list[Event]:
        with session_scope() as s:
            rows = (s.query(AgentEvent).filter(AgentEvent.session_id == self.session_id, AgentEvent.seq > since)
                    .order_by(AgentEvent.seq).all())
            return [Event(r.seq, r.type, r.payload or {}, r.ts.isoformat() + "Z") for r in rows]

    def update(self, **fields) -> None:
        with session_scope() as s:
            row = s.get(AgentSession, self.session_id)
            for k, v in fields.items():
                setattr(row, k, v)

    def row(self) -> dict:
        with session_scope() as s:
            r = s.get(AgentSession, self.session_id)
            return {c.name: getattr(r, c.name) for c in r.__table__.columns}


def derive_messages(events: list[Event], keep_full_results: int = 8, max_chars: int = 60000) -> list[dict]:
    """Project model history from the log (deterministic, so every request is
    reconstructable). Older tool results are elided first when the history
    exceeds ``max_chars`` (compaction); the newest ``keep_full_results`` stay."""
    msgs: list[dict] = []
    cps = [e for e in events if e.type == "context/compacted"]
    if cps:  # checkpoint: first task message + summary + verbatim tail
        cp = cps[-1]
        keep_from = cp.payload.get("keep_from", cp.seq)
        first_user = next((e for e in events if e.type == "user/message"), None)
        tail = [e for e in events if e.seq >= keep_from and e.seq != cp.seq and e.type != "context/compacted"]
        if first_user and first_user.seq < keep_from:
            msgs.append({"role": "user", "content": first_user.payload.get("content", "")})
        msgs.append({"role": "user", "content": "[context checkpoint - summary of the earlier investigation]\n"
                                                + cp.payload.get("summary", "")})
        events = tail
    for e in events:
        p = e.payload
        if e.type == "user/message":
            msgs.append({"role": "user", "content": p.get("content", "")})
        elif e.type == "assistant/message":
            msgs.append({"role": "assistant", "content": p.get("content", ""),
                         "tool_calls": p.get("tool_calls") or []})
        elif e.type == "tool/result":
            msgs.append({"role": "tool", "tool_call_id": p.get("id"), "name": p.get("name"),
                         "content": p.get("content", ""), "is_error": p.get("is_error", False)})
        elif e.type == "approval/resolved":
            msgs.append({"role": "user", "content":
                         f"[harness] Human {p.get('status')} approval #{p.get('approval_id')} for "
                         f"{p.get('tool')}({json.dumps(p.get('args', {}))}). Result: {p.get('summary', '')}"})
    # drop tool results whose call is not in view (cut by a checkpoint)
    called = {c["id"] for m in msgs if m["role"] == "assistant" for c in m.get("tool_calls", [])}
    msgs = [m for m in msgs if m["role"] != "tool" or m["tool_call_id"] in called]
    # orphan tool calls (e.g. a crashed step) get a synthetic error result so
    # every provider sees a well-formed call/result pairing
    seen = {m["tool_call_id"] for m in msgs if m["role"] == "tool"}
    fixed: list[dict] = []
    owed: list[dict] = []

    def flush():
        for c in owed:
            fixed.append({"role": "tool", "tool_call_id": c["id"], "name": c["name"],
                          "content": "[harness] no result recorded (step interrupted)", "is_error": True})
        owed.clear()
    for m in msgs:
        if m["role"] != "tool":
            flush()
        fixed.append(m)
        if m["role"] == "assistant":
            owed.extend(c for c in m.get("tool_calls", []) if c["id"] not in seen)
    flush()
    total = sum(len(m.get("content") or "") for m in fixed)
    if total > max_chars:
        tool_idx = [i for i, m in enumerate(fixed) if m["role"] == "tool"]
        for i in tool_idx[:-keep_full_results] if keep_full_results else tool_idx:
            if total <= max_chars:
                break
            c = fixed[i]["content"]
            if len(c) > 200:
                fixed[i] = {**fixed[i], "content": f"[result elided to save context: {len(c)} chars; "
                                                   f"call {fixed[i]['name']} again if you need it]"}
                total -= len(c) - 120
    return fixed
