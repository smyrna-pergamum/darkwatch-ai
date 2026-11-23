"""Hybrid AI router: local (Ollama) + cloud, with routing strategy."""
from __future__ import annotations

import logging
from typing import Optional

from config.settings import settings
from .local import OllamaClient
from .cloud import CloudClient
from . import prompts

logger = logging.getLogger(__name__)


class AIRouter:
    def __init__(self):
        self.local = OllamaClient()
        self.cloud = CloudClient()
        self.routing = settings.AI_ROUTING.lower()

    def _use_local(self, task: str) -> bool:
        if self.routing == "local":
            return True
        if self.routing == "cloud":
            return False
        # hybrid
        # raw content analysis -> local; summaries/triage/structured -> cloud if available
        if task in ("summary", "ioc", "triage") and self.cloud.available():
            return False
        return self.local.available()

    def analyze_page(self, url: str, title: str, content: str) -> dict:
        content_trunc = content[:6000]
        prompt = prompts.PROMPT_SUMMARY.format(url=url, title=title, content=content_trunc)
        if self._use_local("summary"):
            res = self.local.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        else:
            res = self.cloud.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        if not isinstance(res, dict):
            res = {"summary": str(res), "category": "unknown", "severity": "low",
                   "keywords_found": [], "ioc_hints": []}
        res.setdefault("summary", "")
        res.setdefault("category", "unknown")
        res.setdefault("severity", "low")
        res.setdefault("keywords_found", [])
        res.setdefault("ioc_hints", [])
        return res

    def extract_ioc_ai(self, content: str) -> list:
        prompt = prompts.PROMPT_IOC.format(content=content[:6000])
        if self._use_local("ioc"):
            res = self.local.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        else:
            res = self.cloud.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        if isinstance(res, list):
            return res
        if isinstance(res, dict) and "iocs" in res:
            return res["iocs"]
        return []

    def summarize_run(self, start_url: str, pages: list, iocs_found: int,
                      alerts_raised: int, alerts: list = None,
                      ioc_types: dict = None, keywords: list = None) -> dict:
        """Run-level (post-crawl) AI summary."""
        alerts = alerts or []
        sev_counts = {}
        for a in alerts:
            sev = (a.get("severity") if isinstance(a, dict) else a) or "low"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        page_lines = []
        for p in pages[:12]:
            summary = (p.get("summary") or "").strip().replace("\n", " ")[:300]
            page_lines.append(
                f"- [{(p.get('severity') or 'low')}] {p.get('title') or p.get('url')}: {summary}"
            )
        prompt = prompts.PROMPT_RUN_SUMMARY.format(
            url=start_url,
            pages=len(pages),
            iocs=iocs_found,
            alerts=alerts_raised,
            sev_counts=sev_counts or "{}",
            ioc_types=ioc_types or "{}",
            keywords=", ".join(keywords or []) or "(none)",
            page_summaries="\n".join(page_lines) or "- (no pages analysed)",
        )
        if self._use_local("summary"):
            res = self.local.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        else:
            res = self.cloud.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        if not isinstance(res, dict):
            return {"summary": str(res), "risk_level": "low",
                    "key_findings": [], "recommendations": []}
        res.setdefault("summary", "")
        res.setdefault("risk_level", "low")
        res.setdefault("key_findings", [])
        res.setdefault("recommendations", [])
        return res

    def triage_alert(self, title: str, severity: str, description: str, iocs: list) -> dict:
        prompt = prompts.PROMPT_TRIAGE.format(
            title=title, severity=severity, description=description,
            iocs=", ".join(str(i) for i in iocs[:20]),
        )
        if self._use_local("triage"):
            res = self.local.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        else:
            res = self.cloud.chat_json(prompt, system=prompts.SYSTEM_ANALYST)
        if not isinstance(res, dict):
            return {"true_positive": True, "escalate": True, "reason": "ai unavailable", "recommended_action": "manual review"}
        return res

    def status(self) -> dict:
        return {
            "routing": self.routing,
            "local_available": self.local.available(),
            "local_model": settings.OLLAMA_MODEL,
            "cloud_available": self.cloud.available(),
            "cloud_provider": settings.AI_CLOUD_PROVIDER,
        }