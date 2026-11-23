"""SQLAlchemy models (schema v2)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite has no tz support)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def max_severity(*sevs: str | None) -> str:
    best = "low"
    for s in sevs:
        if s in SEVERITY_RANK and SEVERITY_RANK[s] > SEVERITY_RANK[best]:
            best = s
    return best


class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    url = Column(String(512), unique=True, nullable=False)
    label = Column(String(256), default="")
    keywords = Column(Text, default="")  # extra per-target keywords, comma-separated
    active = Column(Boolean, default=True)
    # approved | pending (suggested by AI, waits for a human)
    approval = Column(String(16), default="approved")
    source = Column(String(16), default="user")  # user | ai
    crawl_mode = Column(String(16), default="standard")  # standard | smart | agent
    agent_goal = Column(Text, default="")
    depth = Column(Integer, nullable=True)
    max_pages = Column(Integer, nullable=True)
    scope = Column(String(16), nullable=True)  # overrides CRAWL_SCOPE
    schedule_interval_min = Column(Integer, nullable=True)  # None/0 = manual
    schedule_cron = Column(String(64), default="")  # alternative to interval
    created_at = Column(DateTime, default=utcnow)
    last_crawled = Column(DateTime, nullable=True)
    last_status = Column(String(16), default="unknown")  # up | down | unknown
    last_error = Column(Text, default="")
    pages = relationship("Page", back_populates="target", cascade="all, delete-orphan")
    runs = relationship("CrawlRun", back_populates="target", cascade="all, delete-orphan")


class WatchItem(Base):
    """Assets / terms the organisation wants to be alerted about."""
    __tablename__ = "watchlist"
    id = Column(Integer, primary_key=True)
    # keyword | brand | domain | email | ip | crypto | regex
    kind = Column(String(16), nullable=False, default="keyword")
    value = Column(String(512), nullable=False)
    severity = Column(String(16), default="medium")
    note = Column(Text, default="")
    active = Column(Boolean, default=True)
    source = Column(String(16), default="user")
    created_at = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_watch_kind_value"),)


class CrawlRun(Base):
    __tablename__ = "crawl_runs"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    start_url = Column(String(1024), default="")
    mode = Column(String(16), default="standard")
    trigger = Column(String(16), default="manual")  # manual | schedule | task | api
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime, nullable=True)
    pages_crawled = Column(Integer, default=0)
    pages_changed = Column(Integer, default=0)
    iocs_found = Column(Integer, default=0)
    alerts_raised = Column(Integer, default=0)
    # queued | running | done | failed | cancelled
    status = Column(String(32), default="queued")
    error = Column(Text, default="")
    notes = Column(Text, default="")
    ai_summary = Column(Text, default="")  # JSON
    agent_log = Column(JSON, default=list)
    target = relationship("Target", back_populates="runs")


class Page(Base):
    __tablename__ = "pages"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    run_id = Column(Integer, ForeignKey("crawl_runs.id", ondelete="SET NULL"), nullable=True)
    url = Column(String(1024), nullable=False, index=True)
    title = Column(String(512), default="")
    content = Column(Text, default="")
    content_hash = Column(String(64), default="")
    previous_hash = Column(String(64), default="")
    changed = Column(Boolean, default=False)
    status_code = Column(Integer, nullable=True)
    crawled_at = Column(DateTime, default=utcnow)
    first_seen = Column(DateTime, default=utcnow)
    depth = Column(Integer, default=0)
    ai_summary = Column(Text, default="")
    ai_severity = Column(String(32), default="low")
    ai_category = Column(String(32), default="unknown")
    ai_analyzed = Column(Boolean, default=False)
    content_purged = Column(Boolean, default=False)
    change_summary = Column(JSON, default=dict)  # line diff vs. previous version
    target = relationship("Target", back_populates="pages")
    sightings = relationship("Sighting", back_populates="page", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="page")


class Indicator(Base):
    """Deduplicated IOC with first/last seen tracking."""
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True)
    ioc_type = Column(String(32), nullable=False)
    value = Column(String(512), nullable=False)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    seen_count = Column(Integer, default=0)
    confidence = Column(Float, default=0.5)
    on_watchlist = Column(Boolean, default=False)
    tags = Column(String(256), default="")
    sightings = relationship("Sighting", back_populates="indicator", cascade="all, delete-orphan")
    __table_args__ = (UniqueConstraint("ioc_type", "value", name="uq_indicator"),)


class Sighting(Base):
    __tablename__ = "sightings"
    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False)
    page_id = Column(Integer, ForeignKey("pages.id"), nullable=True)
    run_id = Column(Integer, nullable=True)
    context = Column(Text, default="")
    source = Column(String(16), default="regex")  # regex | ai
    confidence = Column(Float, default=0.5)
    created_at = Column(DateTime, default=utcnow)
    indicator = relationship("Indicator", back_populates="sightings")
    page = relationship("Page", back_populates="sightings")


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey("pages.id", ondelete="SET NULL"), nullable=True)
    target_id = Column(Integer, nullable=True)
    run_id = Column(Integer, nullable=True)
    url = Column(String(1024), default="")
    # crawler | hibp | intelx | ransomware | ahmia | feed
    source = Column(String(32), default="crawler")
    severity = Column(String(32), default="medium")
    title = Column(String(512), nullable=False)
    description = Column(Text, default="")
    matches = Column(JSON, default=list)  # watchlist hits
    dedup_key = Column(String(64), default="", index=True)
    occurrences = Column(Integer, default=1)
    # new | acknowledged | resolved | false_positive
    status = Column(String(32), default="new")
    notified = Column(Boolean, default=False)
    notify_channels = Column(String(128), default="")
    triage = Column(JSON, default=dict)
    analyst_note = Column(Text, default="")
    analyst_session_id = Column(Integer, nullable=True)
    # DarkWatch AI: threat taxonomy, explainable risk score, IncidentForge case reference
    threat_class = Column(String(32), default="")
    risk_score = Column(Float, default=0.0)
    risk_factors = Column(JSON, default=list)
    incident_ref = Column(String(128), default="")
    created_at = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    page = relationship("Page", back_populates="alerts")


class Task(Base):
    """Automatic / manual follow-up tasks (AI planner output)."""
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True)
    # recrawl | add_target | add_watch | review
    kind = Column(String(32), nullable=False)
    title = Column(String(512), nullable=False)
    reason = Column(Text, default="")
    payload = Column(JSON, default=dict)
    priority = Column(String(16), default="medium")
    # proposed | approved | done | rejected | failed
    status = Column(String(16), default="proposed")
    source = Column(String(16), default="ai")
    target_id = Column(Integer, nullable=True)
    run_id = Column(Integer, nullable=True)
    due_at = Column(DateTime, nullable=True)
    result = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class FeedEntry(Base):
    """Cached entries from public threat feeds (CISA KEV, Feodo, ...)."""
    __tablename__ = "feed_entries"
    id = Column(Integer, primary_key=True)
    feed = Column(String(32), nullable=False)
    ioc_type = Column(String(32), nullable=False)
    value = Column(String(512), nullable=False, index=True)
    info = Column(JSON, default=dict)
    updated_at = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("feed", "value", name="uq_feed_value"),)


class SourceRun(Base):
    """One execution of an external intelligence source (HIBP, IntelX, ...)."""
    __tablename__ = "source_runs"
    id = Column(Integer, primary_key=True)
    source = Column(String(32), nullable=False, index=True)
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(16), default="running")  # running | done | failed | skipped
    queries = Column(Integer, default=0)
    findings = Column(Integer, default=0)
    alerts = Column(Integer, default=0)
    error = Column(Text, default="")


class AgentSession(Base):
    """One agent conversation (harness session). Its source of truth is the
    append-only ``agent_events`` log; the columns here are a summary."""
    __tablename__ = "agent_sessions"
    id = Column(Integer, primary_key=True)
    agent = Column(String(32), nullable=False, default="analyst")
    title = Column(String(512), default="")
    subject_type = Column(String(32), default="")  # alert | free
    subject_id = Column(Integer, nullable=True)
    trigger = Column(String(16), default="manual")  # manual | auto | api
    # idle | queued | running | waiting_approval | done | failed | cancelled
    status = Column(String(24), default="idle")
    provider = Column(String(32), default="")
    model = Column(String(128), default="")
    turns = Column(Integer, default=0)
    steps = Column(Integer, default=0)
    tool_calls = Column(Integer, default=0)
    report = Column(JSON, nullable=True)
    error = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class AgentEvent(Base):
    """Durable session event (turn/*, step/*, user/message, assistant/message,
    tool/call, tool/result, approval/*, report/submitted). Model-visible means logged."""
    __tablename__ = "agent_events"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    type = Column(String(32), nullable=False)
    payload = Column(JSON, default=dict)
    ts = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("session_id", "seq", name="uq_agent_event_seq"),)


class AgentApproval(Base):
    """A tool call the policy routed to a human ("ask")."""
    __tablename__ = "agent_approvals"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    call_id = Column(String(64), default="")
    tool = Column(String(64), nullable=False)
    args = Column(JSON, default=dict)
    permission = Column(String(16), default="write")
    reason = Column(Text, default="")
    # pending | approved | rejected | failed
    status = Column(String(16), default="pending")
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    decided_at = Column(DateTime, nullable=True)
    decided_by = Column(String(64), default="")


class AIProvider(Base):
    """A user-configured model endpoint (OpenAI-compatible, Ollama, llama.cpp, Anthropic)."""
    __tablename__ = "ai_providers"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    kind = Column(String(24), nullable=False, default="openai_compat")  # openai_compat | ollama | llamacpp | anthropic
    preset = Column(String(32), default="custom")
    base_url = Column(String(512), default="")
    api_key = Column(String(512), default="")
    model = Column(String(256), default="")
    # local: same machine / LAN -> may see raw dark-web text. remote: summaries only (redacted)
    trust = Column(String(8), default="local")
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=100)  # lower = tried first
    supports_tools = Column(Boolean, default=True)
    context_window = Column(Integer, default=0)  # tokens; 0 = auto-detect
    created_at = Column(DateTime, default=utcnow)


class LocalModel(Base):
    """A GGUF model file usable by llama.cpp."""
    __tablename__ = "local_models"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)
    path = Column(String(1024), nullable=False)
    source = Column(String(16), default="path")  # upload | url | path
    url = Column(String(2048), default="")
    size_bytes = Column(Integer, default=0)
    status = Column(String(16), default="ready")  # downloading | ready | failed
    progress = Column(Float, default=1.0)
    error = Column(Text, default="")
    meta = Column(JSON, default=dict)  # architecture, context length, quantisation ...
    active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)


class Feedback(Base):
    """Human feedback on an alert / AI verdict - the only source the system learns from."""
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    session_id = Column(Integer, nullable=True)
    source = Column(String(16), default="explicit")  # explicit | status (implicit, from alert status changes)
    ai_verdict = Column(String(24), default="")        # what the AI said (if any)
    agree = Column(Boolean, nullable=True)             # human agrees with the AI verdict
    label = Column(String(24), default="")             # true_positive | false_positive | benign | needs_more_info
    severity = Column(String(16), default="")
    comment = Column(Text, default="")
    provider = Column(String(128), default="")
    actor = Column(String(64), default="user")
    created_at = Column(DateTime, default=utcnow)


class Lesson(Base):
    """A human-confirmed insight retrieved into future investigations."""
    __tablename__ = "lessons"
    id = Column(Integer, primary_key=True)
    title = Column(String(300), nullable=False)
    text = Column(Text, nullable=False)
    verdict = Column(String(24), default="")
    severity = Column(String(16), default="")
    terms = Column(JSON, default=list)        # watch terms / keywords it applies to
    category = Column(String(32), default="")
    example = Column(Text, default="")        # short masked context of the source case
    source_alert_id = Column(Integer, nullable=True)
    source = Column(String(16), default="feedback")  # feedback | manual | ai_draft
    status = Column(String(16), default="active")    # active | proposed | disabled
    uses = Column(Integer, default=0)
    helpful = Column(Integer, default=0)
    unhelpful = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class SuppressionRule(Base):
    """Context rule for a noisy watch term: suppress or downgrade matches."""
    __tablename__ = "suppression_rules"
    id = Column(Integer, primary_key=True)
    watch_kind = Column(String(16), default="keyword")
    watch_value = Column(String(512), nullable=False)
    context_keywords = Column(JSON, default=list)  # any of these near the page -> rule applies
    host = Column(String(256), default="")          # optional: only on this site
    action = Column(String(16), default="downgrade")  # downgrade | suppress
    severity = Column(String(16), default="low")      # target severity for downgrade
    reason = Column(Text, default="")
    created_by = Column(String(16), default="user")   # user | ai | stats
    status = Column(String(16), default="proposed")   # proposed | active | disabled
    hits = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow)


class EvalCase(Base):
    """A corrected case frozen as a regression test for the analyst agent."""
    __tablename__ = "eval_cases"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    alert = Column(JSON, default=dict)        # title, severity, source, matches
    page_title = Column(String(512), default="")
    page_content = Column(Text, default="")   # masked text (credentials already masked)
    indicators = Column(JSON, default=list)
    history = Column(JSON, default=list)      # similar past alerts with their statuses
    expected = Column(JSON, default=list)     # accepted verdicts
    note = Column(Text, default="")
    source_alert_id = Column(Integer, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=utcnow, index=True)
    actor = Column(String(64), default="system")
    action = Column(String(64), nullable=False)
    detail = Column(Text, default="")


Index("ix_alert_status_sev", Alert.status, Alert.severity)
Index("ix_sighting_page", Sighting.page_id)
