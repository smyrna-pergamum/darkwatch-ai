"""Watch-term quality statistics and context suppression rules."""
from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from ..storage.db import audit, session_scope
from ..storage.models import SEVERITY_RANK, Alert, Feedback, SuppressionRule, WatchItem
from .lessons import tokens


def _labels(s) -> dict[int, str]:
    """alert_id -> best label (explicit feedback beats status-derived)."""
    out: dict[int, tuple[int, str]] = {}
    for f in s.query(Feedback).filter(Feedback.label != "").order_by(Feedback.id):
        rank = 2 if f.source == "explicit" else 1
        if f.alert_id and (f.alert_id not in out or rank >= out[f.alert_id][0]):
            out[f.alert_id] = (rank, f.label)
    for a in s.query(Alert.id, Alert.status):
        if a.id not in out and a.status == "false_positive":
            out[a.id] = (1, "false_positive")
    return {k: v[1] for k, v in out.items()}


def term_stats() -> list[dict]:
    with session_scope() as s:
        labels = _labels(s)
        items = s.query(WatchItem).all()
        per: dict[tuple[str, str], dict] = {(w.kind, w.value.lower()): {
            "id": w.id, "kind": w.kind, "value": w.value, "severity": w.severity, "active": w.active,
            "alerts": 0, "tp": 0, "fp": 0, "unlabeled": 0} for w in items}
        for a in s.query(Alert).filter(Alert.source == "crawler"):
            for m in a.matches or []:
                key = (m.get("kind"), str(m.get("value", "")).lower())
                if key not in per:
                    continue
                d = per[key]
                d["alerts"] += 1
                lab = labels.get(a.id)
                if lab in ("false_positive", "benign"):
                    d["fp"] += 1
                elif lab == "true_positive":
                    d["tp"] += 1
                else:
                    d["unlabeled"] += 1
        rules = Counter((r.watch_kind, r.watch_value.lower()) for r in s.query(SuppressionRule).filter_by(status="active"))
        out = []
        for key, d in per.items():
            labeled = d["tp"] + d["fp"]
            d["fp_rate"] = round(d["fp"] / labeled, 2) if labeled else None
            d["active_rules"] = rules.get(key, 0)
            d["noisy"] = bool(labeled >= 3 and d["fp_rate"] is not None and d["fp_rate"] >= 0.6)
            out.append(d)
        return sorted(out, key=lambda d: (-(d["fp_rate"] or 0), -d["alerts"]))


def propose(min_labeled: int = 3, min_fp_rate: float = 0.6, max_keywords: int = 4) -> list[int]:
    """For noisy terms, find words that appear around false positives but never
    around true positives, and propose a downgrade rule (status: proposed)."""
    created = []
    with session_scope() as s:
        labels = _labels(s)
        existing = {(r.watch_kind, r.watch_value.lower()) for r in
                    s.query(SuppressionRule).filter(SuppressionRule.status.in_(("proposed", "active")))}
        for st in term_stats():
            labeled = st["tp"] + st["fp"]
            if labeled < min_labeled or (st["fp_rate"] or 0) < min_fp_rate:
                continue
            key = (st["kind"], st["value"].lower())
            if key in existing:
                continue
            fp_ctx, tp_ctx = Counter(), Counter()
            hosts = Counter()
            for a in s.query(Alert).filter(Alert.source == "crawler"):
                ms = [m for m in a.matches or [] if (m.get("kind"), str(m.get("value", "")).lower()) == key]
                if not ms:
                    continue
                lab = labels.get(a.id)
                toks = set()
                for m in ms:
                    toks |= set(tokens(m.get("context") or ""))
                toks |= set(tokens(a.title or ""))
                toks.discard(st["value"].lower())
                if lab in ("false_positive", "benign"):
                    fp_ctx.update(toks)
                    hosts[urlparse(a.url or "").hostname or ""] += 1
                elif lab == "true_positive":
                    tp_ctx.update(toks)
            kws = [t for t, c in fp_ctx.most_common(40) if c >= 2 and t not in tp_ctx and not t.isdigit()][:max_keywords]
            host = ""
            if not kws and hosts and st["tp"] == 0:
                h, c = hosts.most_common(1)[0]
                host = h if c >= min_labeled else ""
            if not kws and not host:
                continue
            r = SuppressionRule(watch_kind=st["kind"], watch_value=st["value"], context_keywords=kws, host=host,
                                action="downgrade", severity="low", created_by="stats", status="proposed",
                                reason=(f"{st['fp']} of {labeled} labelled alerts for '{st['value']}' were false positives; "
                                        + (f"they share the words {', '.join(kws)} which never appear in true positives."
                                           if kws else f"all came from {host}.")))
            s.add(r)
            s.flush()
            created.append(r.id)
    if created:
        audit("rules.propose", f"{len(created)} rule(s) proposed")
    return created


def apply(matches: list[dict], text: str, url: str = "", session=None) -> tuple[list[dict], list[dict]]:
    """Apply active rules to watchlist matches. Returns (matches, applied).
    Pass the caller's ``session`` when it already holds a write transaction
    (SQLite allows one writer: a second session would wait for the lock)."""
    if not matches:
        return matches, []
    if session is not None:
        return _apply(session, matches, text, url)
    with session_scope() as s:
        return _apply(s, matches, text, url)


def _apply(s, matches: list[dict], text: str, url: str) -> tuple[list[dict], list[dict]]:
    keys = {(m.get("kind"), str(m.get("value", "")).lower()) for m in matches}
    if keys:
        rules = [r for r in s.query(SuppressionRule).filter_by(status="active")
                 if (r.watch_kind, r.watch_value.lower()) in keys]
        if not rules:
            return matches, []
        low = (text or "").lower()
        host = (urlparse(url or "").hostname or "").lower()
        out, applied = [], []
        for m in matches:
            key = (m.get("kind"), str(m.get("value", "")).lower())
            hit = None
            for r in rules:
                if (r.watch_kind, r.watch_value.lower()) != key:
                    continue
                if r.host and r.host.lower() != host:
                    continue
                kws = [k.lower() for k in (r.context_keywords or [])]
                if kws and not any(k in low for k in kws):
                    continue
                if not kws and not r.host:
                    continue
                hit = r
                break
            if hit is None:
                out.append(m)
                continue
            hit.hits = (hit.hits or 0) + 1
            applied.append({"rule_id": hit.id, "value": m.get("value"), "action": hit.action})
            if hit.action == "downgrade":
                sev = hit.severity if SEVERITY_RANK.get(hit.severity, 0) < SEVERITY_RANK.get(m.get("severity"), 1) \
                    else m.get("severity")
                out.append({**m, "severity": sev, "rule": hit.id})
        return out, applied


def to_dict(r: SuppressionRule) -> dict:
    return {"id": r.id, "watch_kind": r.watch_kind, "watch_value": r.watch_value,
            "context_keywords": r.context_keywords or [], "host": r.host, "action": r.action, "severity": r.severity,
            "reason": r.reason, "created_by": r.created_by, "status": r.status, "hits": r.hits,
            "created_at": r.created_at.isoformat() + "Z"}
