"""SQLAlchemy models for dark web monitor."""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float, JSON, ForeignKey, Boolean,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    url = Column(String(512), unique=True, nullable=False)
    label = Column(String(256), default="")
    keywords = Column(Text, default="")  # comma-separated watchlist
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_crawled = Column(DateTime, nullable=True)
    pages = relationship("Page", back_populates="target", cascade="all, delete-orphan")


class Page(Base):
    __tablename__ = "pages"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    url = Column(String(1024), nullable=False)
    title = Column(String(512), default="")
    content = Column(Text, default="")
    content_hash = Column(String(64), default="")
    status_code = Column(Integer, nullable=True)
    crawled_at = Column(DateTime, default=datetime.utcnow)
    depth = Column(Integer, default=0)
    ai_summary = Column(Text, default="")
    ai_severity = Column(String(32), default="low")
    target = relationship("Target", back_populates="pages")
    iocs = relationship("IOC", back_populates="page", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="page", cascade="all, delete-orphan")


class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey("pages.id"), nullable=True)
    ioc_type = Column(String(32), nullable=False)  # ip, email, hash, crypto, url, domain
    value = Column(String(512), nullable=False)
    context = Column(Text, default="")
    confidence = Column(Float, default=0.5)
    created_at = Column(DateTime, default=datetime.utcnow)
    page = relationship("Page", back_populates="iocs")


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    page_id = Column(Integer, ForeignKey("pages.id"), nullable=True)
    severity = Column(String(32), default="medium")
    title = Column(String(512), nullable=False)
    description = Column(Text, default="")
    notified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    page = relationship("Page", back_populates="alerts")


class CrawlRun(Base):
    __tablename__ = "crawl_runs"
    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    pages_crawled = Column(Integer, default=0)
    iocs_found = Column(Integer, default=0)
    alerts_raised = Column(Integer, default=0)
    status = Column(String(32), default="running")
    notes = Column(Text, default="")
    ai_summary = Column(Text, default="")  # JSON: run-level AI summary