"""Database session management."""
from __future__ import annotations

from contextlib import contextmanager
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, Session

from config.settings import settings
from .models import Base


_engine = create_engine(settings.DATABASE_URL, future=True)
_SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(_engine)
    # Light-weight migration for existing SQLite databases.
    insp = inspect(_engine)
    tables = set(insp.get_table_names())
    if "crawl_runs" in tables:
        cols = {c["name"] for c in insp.get_columns("crawl_runs")}
        if "ai_summary" not in cols:
            with _engine.begin() as conn:
                conn.exec_driver_sql("ALTER TABLE crawl_runs ADD COLUMN ai_summary TEXT DEFAULT ''")


def get_session() -> Session:
    return _SessionLocal()


@contextmanager
def session_scope():
    s = _SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()