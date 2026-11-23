"""DarkWatch AI intelligence models: organisations (tenants), evidence with a
chain of custody, and threat actors.

Collection (targets, pages, indicators) is shared infrastructure; tenants own
*assets* (links to watch items) and see the alerts their assets matched."""
from __future__ import annotations

from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint,
)

from .models import Base, utcnow


class Organization(Base):
    """A tenant: a company / brand whose assets are monitored."""
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, unique=True)
    slug = Column(String(80), nullable=False, unique=True)
    sector = Column(String(64), default="")
    country = Column(String(64), default="")
    description = Column(Text, default="")
    active = Column(Boolean, default=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(16), default="low")
    risk_factors = Column(JSON, default=list)
    risk_updated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class OrgAsset(Base):
    """Link organisation -> watch item. Several tenants may share one watch item."""
    __tablename__ = "org_assets"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    watch_id = Column(Integer, ForeignKey("watchlist.id", ondelete="CASCADE"), nullable=False, index=True)
    # domain | brand | email | employee_email | executive | keyword | ip | crypto | regex
    asset_type = Column(String(24), default="domain")
    label = Column(String(200), default="")
    created_at = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("org_id", "watch_id", name="uq_org_asset"),)


class AlertOrg(Base):
    """Which tenants an alert concerns (derived from matched assets)."""
    __tablename__ = "alert_orgs"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("alert_id", "org_id", name="uq_alert_org"),)


class OrgApiKey(Base):
    """Tenant API key: grants access to /api/orgs/{org_id}/... only. Stored hashed."""
    __tablename__ = "org_api_keys"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), default="")
    prefix = Column(String(12), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_used = Column(DateTime, nullable=True)


class Evidence(Base):
    """A preserved, hashed snapshot of what was observed (page or source record)."""
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    page_id = Column(Integer, ForeignKey("pages.id", ondelete="SET NULL"), nullable=True)
    kind = Column(String(24), default="page_snapshot")  # page_snapshot | source_record | manual
    url = Column(String(1024), default="")
    sha256 = Column(String(64), nullable=False, index=True)
    size_bytes = Column(Integer, default=0)
    path = Column(String(1024), nullable=False)   # relative to EVIDENCE_DIR
    captured_at = Column(DateTime, default=utcnow)
    captured_by = Column(String(64), default="system")
    note = Column(Text, default="")
    meta = Column(JSON, default=dict)
    legal_hold = Column(Boolean, default=False)
    # anchor of the custody chain: truncating the log is detected by verify()
    custody_head = Column(String(64), default="")
    custody_count = Column(Integer, default=0)


class CustodyEvent(Base):
    """Hash-chained chain-of-custody log entry for one evidence item."""
    __tablename__ = "custody_events"
    id = Column(Integer, primary_key=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    ts = Column(DateTime, default=utcnow)
    actor = Column(String(64), default="system")
    action = Column(String(32), nullable=False)  # captured | verified | exported | escalated | note | hold
    detail = Column(Text, default="")
    prev_hash = Column(String(64), default="")
    entry_hash = Column(String(64), nullable=False)
    __table_args__ = (UniqueConstraint("evidence_id", "seq", name="uq_custody_seq"),)


class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False, unique=True)
    kind = Column(String(24), default="individual")  # individual | ransomware_group | group | unknown
    aliases = Column(JSON, default=list)
    description = Column(Text, default="")
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    mention_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    tags = Column(JSON, default=list)
    profile = Column(JSON, default=dict)  # derived / AI profile
    created_at = Column(DateTime, default=utcnow)


class ActorHandle(Base):
    """A contact / identifier attributed to an actor (forum nick, Telegram, Jabber, wallet...)."""
    __tablename__ = "actor_handles"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False, index=True)
    platform = Column(String(24), nullable=False)  # forum | telegram | jabber | tox | email | crypto | site
    value = Column(String(300), nullable=False)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("platform", "value", name="uq_actor_handle"),)


class ActorSighting(Base):
    __tablename__ = "actor_sightings"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False, index=True)
    page_id = Column(Integer, ForeignKey("pages.id", ondelete="SET NULL"), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    source = Column(String(24), default="forum")  # forum | ransomware | manual
    host = Column(String(256), default="")
    context = Column(Text, default="")
    ts = Column(DateTime, default=utcnow)
