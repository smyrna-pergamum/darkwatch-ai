"""Evidence preservation: hashed snapshots with a hash-chained chain of custody.

Each item is a canonical JSON record (what was seen, where, when, by which
collector) stored gzip-compressed and content-addressed by the SHA-256 of the
uncompressed canonical bytes. Every action on the item (captured, verified,
exported, escalated ...) is appended to a custody log in which each entry's
hash covers the previous entry, so silent edits or deletions are detectable.

Credentials were masked before page content was stored - evidence never
contains plaintext passwords."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import zipfile
from pathlib import Path

from config.settings import DATA_DIR, settings
from .. import __version__
from ..storage.models import Alert, Page, utcnow
from ..storage.models_intel import CustodyEvent, Evidence

SCHEMA = "darkwatch.evidence/1"


class EvidenceError(RuntimeError):
    pass


def evidence_dir() -> Path:
    d = Path(settings.EVIDENCE_DIR) if settings.EVIDENCE_DIR else DATA_DIR / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    return d


def canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _iso(dt) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _store(data: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(data).hexdigest()
    now = utcnow()
    rel = Path(f"{now:%Y}") / f"{now:%m}" / f"{digest}.json.gz"
    full = evidence_dir() / rel
    if not full.exists():
        full.parent.mkdir(parents=True, exist_ok=True)
        tmp = full.with_suffix(".tmp")
        with gzip.open(tmp, "wb") as fh:
            fh.write(data)
        tmp.replace(full)
    return digest, rel.as_posix()


def _resolve(ev: Evidence) -> Path:
    base = evidence_dir().resolve()
    p = (base / ev.path).resolve()
    if base not in p.parents:
        raise EvidenceError("evidence path escapes the evidence directory")
    return p


def _entry_hash(prev: str, ev: Evidence, seq: int, ts, actor: str, action: str, detail: str) -> str:
    blob = "|".join([prev, str(ev.id), str(seq), _iso(ts) or "", actor, action, detail, ev.sha256])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def add_custody(s, ev: Evidence, action: str, actor: str = "system", detail: str = "") -> CustodyEvent:
    last = (s.query(CustodyEvent).filter_by(evidence_id=ev.id).order_by(CustodyEvent.seq.desc()).first())
    seq = (last.seq + 1) if last else 1
    prev = last.entry_hash if last else ""
    ts = utcnow()
    detail = (detail or "")[:2000]
    ce = CustodyEvent(evidence_id=ev.id, seq=seq, ts=ts, actor=actor[:64], action=action[:32], detail=detail,
                      prev_hash=prev, entry_hash=_entry_hash(prev, ev, seq, ts, actor[:64], action[:32], detail))
    s.add(ce)
    ev.custody_head, ev.custody_count = ce.entry_hash, seq
    s.flush()
    return ce


def _captured_detail(ev: Evidence) -> str:
    """The first custody entry binds the item's metadata, so editing it breaks verification."""
    return (f"sha256={ev.sha256} size={ev.size_bytes} path={ev.path} kind={ev.kind} alert={ev.alert_id} "
            f"page={ev.page_id} captured_at={_iso(ev.captured_at)}")


def _collector() -> dict:
    return {"tool": "DarkWatch AI (darkweb-monitor)", "version": __version__,
            "method": "passive GET over Tor" if settings.TOR_ENABLED else "passive GET"}


def page_record(page: Page, alert: Alert | None = None) -> dict:
    return {"schema": SCHEMA, "kind": "page_snapshot", "url": page.url, "title": page.title,
            "status_code": page.status_code, "content_sha256": page.content_hash,
            "content": page.content or "", "content_purged": bool(page.content_purged),
            "crawled_at": _iso(page.crawled_at), "first_seen": _iso(page.first_seen),
            "run_id": page.run_id, "target_id": page.target_id, "alert_id": alert.id if alert else None,
            "captured_at": _iso(utcnow()), "collector": _collector(),
            "notes": "credentials in content were masked before storage"}


def alert_record(alert: Alert) -> dict:
    return {"schema": SCHEMA, "kind": "source_record", "source": alert.source, "url": alert.url,
            "title": alert.title, "description": alert.description, "severity": alert.severity,
            "matches": alert.matches or [], "alert_id": alert.id, "first_seen": _iso(alert.created_at),
            "last_seen": _iso(alert.last_seen), "captured_at": _iso(utcnow()), "collector": _collector()}


def capture(s, record: dict, *, alert_id: int | None = None, page_id: int | None = None,
            actor: str = "system", note: str = "") -> Evidence:
    # identical observation (everything except the capture time) -> reuse the existing item
    subject = hashlib.sha256(canonical({k: v for k, v in record.items() if k != "captured_at"})).hexdigest()
    for dup in s.query(Evidence).filter_by(alert_id=alert_id, page_id=page_id).all():
        if (dup.meta or {}).get("subject_sha256") == subject:
            return dup
    data = canonical(record)
    digest, rel = _store(data)
    ev = Evidence(alert_id=alert_id, page_id=page_id, kind=record.get("kind", "manual"),
                  url=str(record.get("url") or "")[:1024], sha256=digest, size_bytes=len(data), path=rel,
                  captured_by=actor[:64], note=note[:2000],
                  meta={"title": str(record.get("title") or "")[:300], "schema": SCHEMA,
                        "subject_sha256": subject})
    s.add(ev)
    s.flush()
    if ev.captured_at is None:
        ev.captured_at = utcnow()
    add_custody(s, ev, "captured", actor, _captured_detail(ev))
    return ev


def capture_for_alert(s, alert: Alert, actor: str = "system", note: str = "") -> Evidence:
    page = s.get(Page, alert.page_id) if alert.page_id else None
    if page is not None and (page.content or "").strip():
        return capture(s, page_record(page, alert), alert_id=alert.id, page_id=page.id, actor=actor, note=note)
    return capture(s, alert_record(alert), alert_id=alert.id, actor=actor, note=note)


def read_content(ev: Evidence) -> bytes:
    try:
        with gzip.open(_resolve(ev), "rb") as fh:
            return fh.read()
    except FileNotFoundError as e:
        raise EvidenceError("evidence file is missing") from e


def verify(s, ev: Evidence, actor: str = "system", log: bool = True) -> dict:
    problems: list[str] = []
    actual = ""
    try:
        actual = hashlib.sha256(read_content(ev)).hexdigest()
    except (EvidenceError, OSError) as e:
        problems.append(str(e))
    file_ok = actual == ev.sha256
    if actual and not file_ok:
        problems.append("content hash mismatch - file was altered")
    chain_ok, prev = True, ""
    events = s.query(CustodyEvent).filter_by(evidence_id=ev.id).order_by(CustodyEvent.seq).all()
    for i, ce in enumerate(events, start=1):
        expect = _entry_hash(prev, ev, ce.seq, ce.ts, ce.actor, ce.action, ce.detail or "")
        if ce.seq != i or ce.prev_hash != prev or ce.entry_hash != expect:
            chain_ok = False
            problems.append(f"custody entry #{ce.seq} does not chain")
            break
        prev = ce.entry_hash
    if chain_ok and (not events or events[0].action != "captured" or (events[0].detail or "") != _captured_detail(ev)):
        chain_ok = False
        problems.append("evidence metadata does not match the capture record")
    if chain_ok and (prev != (ev.custody_head or "") or len(events) != (ev.custody_count or 0)):
        chain_ok = False
        problems.append("custody log was truncated or the chain head does not match")
    ok = file_ok and chain_ok
    if log:
        add_custody(s, ev, "verified", actor, "ok" if ok else "; ".join(problems)[:500])
    return {"evidence_id": ev.id, "ok": ok, "file_ok": file_ok, "chain_ok": chain_ok,
            "sha256": ev.sha256, "actual_sha256": actual, "custody_events": len(events), "problems": problems}


def evidence_dict(s, ev: Evidence, custody: bool = False) -> dict:
    d = {"id": ev.id, "alert_id": ev.alert_id, "page_id": ev.page_id, "kind": ev.kind, "url": ev.url,
         "sha256": ev.sha256, "size_bytes": ev.size_bytes, "captured_at": _iso(ev.captured_at),
         "captured_by": ev.captured_by, "note": ev.note, "legal_hold": ev.legal_hold, "meta": ev.meta or {}}
    if custody:
        d["custody"] = [{"seq": c.seq, "ts": _iso(c.ts), "actor": c.actor, "action": c.action,
                         "detail": c.detail, "entry_hash": c.entry_hash, "prev_hash": c.prev_hash}
                        for c in s.query(CustodyEvent).filter_by(evidence_id=ev.id).order_by(CustodyEvent.seq)]
    return d


def export_bundle(s, alert_id: int, actor: str = "system") -> bytes:
    """ZIP with manifest.json, every evidence record and SHA256SUMS."""
    alert = s.get(Alert, alert_id)
    if not alert:
        raise EvidenceError("alert not found")
    items = s.query(Evidence).filter_by(alert_id=alert_id).order_by(Evidence.id).all()
    if not items:
        raise EvidenceError("no evidence for this alert")
    buf = io.BytesIO()
    sums = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for ev in items:
            add_custody(s, ev, "exported", actor, f"bundle for alert #{alert_id}")
            name = f"evidence/{ev.id}-{ev.sha256[:16]}.json"
            z.writestr(name, read_content(ev))
            sums.append(f"{ev.sha256}  {name}")
        manifest = {"schema": "darkwatch.bundle/1", "generated_at": _iso(utcnow()), "generated_by": actor,
                    "alert": {"id": alert.id, "title": alert.title, "severity": alert.severity,
                              "source": alert.source, "url": alert.url, "threat_class": alert.threat_class,
                              "risk_score": alert.risk_score, "created_at": _iso(alert.created_at)},
                    "evidence": [evidence_dict(s, ev, custody=True) for ev in items]}
        z.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        z.writestr("SHA256SUMS", "\n".join(sums) + "\n")
    return buf.getvalue()
