"""Database engine, sessions and a small additive migration helper."""
from __future__ import annotations

import logging
from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker

from config.settings import ensure_dirs, settings
from .models import AuditLog, Base

logger = logging.getLogger(__name__)

_engine = None
_SessionLocal = None


def _make_engine(url: str):
    kwargs = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    eng = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragmas(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    return eng


def configure(url: str | None = None) -> None:
    """(Re)configure the engine - used by tests to point at a temp DB."""
    global _engine, _SessionLocal
    ensure_dirs()
    _engine = _make_engine(url or settings.DATABASE_URL)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False,
                                 expire_on_commit=False, future=True)


def engine():
    if _engine is None:
        configure()
    return _engine


def _add_missing_columns() -> list[str]:
    """Additive migration: add columns that exist in the models but not in the DB.

    Covers upgrades from schema v1 without losing data. Destructive changes
    are never performed automatically.
    """
    eng = engine()
    insp = inspect(eng)
    existing_tables = set(insp.get_table_names())
    added = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            coltype = col.type.compile(dialect=eng.dialect)
            default = ""
            d = col.default.arg if col.default is not None and not callable(col.default.arg) else None
            if isinstance(d, bool):
                default = f" DEFAULT {1 if d else 0}"
            elif isinstance(d, (int, float)):
                default = f" DEFAULT {d}"
            elif isinstance(d, str):
                default = " DEFAULT '" + d.replace("'", "''") + "'"
            with eng.begin() as conn:
                conn.exec_driver_sql(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {coltype}{default}')
            added.append(f"{table.name}.{col.name}")
    if added:
        logger.info("schema upgraded, added columns: %s", ", ".join(added))
    return added


def init_db() -> None:
    eng = engine()
    Base.metadata.create_all(eng)
    _add_missing_columns()


def get_session() -> Session:
    if _SessionLocal is None:
        configure()
    return _SessionLocal()


@contextmanager
def session_scope():
    s = get_session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def audit(action: str, detail: str = "", actor: str = "system") -> None:
    try:
        with session_scope() as s:
            s.add(AuditLog(action=action, detail=detail[:4000], actor=actor))
    except Exception:  # audit must never break the caller
        logger.exception("audit write failed")
