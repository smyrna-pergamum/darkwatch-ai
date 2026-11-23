"""Alert notification channels."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import requests

from config.settings import settings

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _meets_threshold(sev: str) -> bool:
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(settings.ALERT_MIN_SEVERITY, 0)


class Notifier:
    def __init__(self):
        self.webhook = settings.ALERT_WEBHOOK_URL

    def notify(self, title: str, description: str, severity: str = "medium",
               iocs: list = None, url: str = "") -> bool:
        if not _meets_threshold(severity):
            return False
        iocs = iocs or []
        if settings.ALERT_CONSOLE:
            print(f"\n[ALERT][{severity.upper()}] {title}\n  {description}\n  URL: {url}\n  IOCs: {', '.join(str(i) for i in iocs[:10])}\n")
        if settings.ALERT_FILE:
            try:
                Path(settings.ALERT_FILE_PATH).parent.mkdir(parents=True, exist_ok=True)
                with open(settings.ALERT_FILE_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "ts": datetime.utcnow().isoformat(),
                        "severity": severity,
                        "title": title,
                        "description": description,
                        "url": url,
                        "iocs": iocs[:20],
                    }) + "\n")
            except Exception as e:
                logger.warning("alert file write failed: %s", e)
        if self.webhook:
            try:
                payload = {"content": f"**[{severity.upper()}] {title}**\n{description}\nURL: {url}\nIOCs: {', '.join(str(i) for i in iocs[:10])}"}
                requests.post(self.webhook, json=payload, timeout=10)
            except Exception as e:
                logger.warning("webhook failed: %s", e)
        return True