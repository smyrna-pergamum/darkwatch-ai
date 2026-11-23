"""Alert notification channels: console, file, webhook (Discord / Slack /
Teams / generic), Telegram bot, e-mail. URLs and IOCs are defanged."""
from __future__ import annotations

import json
import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import requests

from config.settings import settings
from ..ioc.extractor import defang
from ..storage.models import SEVERITY_RANK

logger = logging.getLogger(__name__)
EMOJI = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def meets_threshold(sev: str) -> bool:
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(settings.ALERT_MIN_SEVERITY, 1)


def _webhook_format(url: str) -> str:
    fmt = settings.ALERT_WEBHOOK_FORMAT.lower()
    if fmt != "auto":
        return fmt
    if "discord.com" in url or "discordapp.com" in url:
        return "discord"
    if "hooks.slack.com" in url:
        return "slack"
    if "webhook.office.com" in url or "logic.azure.com" in url:
        return "teams"
    return "generic"


class Notifier:
    def channels(self) -> list[str]:
        ch = []
        if settings.ALERT_CONSOLE:
            ch.append("console")
        if settings.ALERT_FILE:
            ch.append("file")
        if settings.ALERT_WEBHOOK_URL:
            ch.append("webhook")
        if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
            ch.append("telegram")
        if settings.SMTP_HOST and settings.SMTP_TO:
            ch.append("email")
        return ch

    def notify(self, title: str, description: str, severity: str = "medium",
               iocs: list | None = None, url: str = "", force: bool = False) -> list[str]:
        """Send to every configured channel. Returns channels that succeeded."""
        if not force and not meets_threshold(severity):
            return []
        iocs = [defang(str(i)) for i in (iocs or [])][:10]
        safe_url = defang(url)
        text = (f"{EMOJI.get(severity, '')} [{severity.upper()}] {title}\n{description}\n"
                f"URL: {safe_url}\nIOCs: {', '.join(iocs) or '-'}")
        sent = []
        for ch in self.channels():
            try:
                getattr(self, f"_send_{ch}")(title, description, severity, iocs, safe_url, text)
                sent.append(ch)
            except Exception as e:  # noqa: BLE001
                logger.warning("alert channel %s failed: %s", ch, e)
        return sent

    # channels ---------------------------------------------------------------
    def _send_console(self, title, desc, sev, iocs, url, text):
        print("\n" + text + "\n")

    def _send_file(self, title, desc, sev, iocs, url, text):
        p = Path(settings.ALERT_FILE_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "severity": sev,
                                "title": title, "description": desc, "url": url, "iocs": iocs},
                               ensure_ascii=False) + "\n")

    def _send_webhook(self, title, desc, sev, iocs, url, text):
        hook = settings.ALERT_WEBHOOK_URL
        fmt = _webhook_format(hook)
        if fmt == "discord":
            payload = {"content": text[:1990]}
        elif fmt == "slack":
            payload = {"text": text[:3900]}
        elif fmt == "teams":
            payload = {"@type": "MessageCard", "@context": "https://schema.org/extensions",
                       "summary": title, "title": f"[{sev.upper()}] {title}", "text": text.replace("\n", "<br>")}
        else:
            payload = {"title": title, "severity": sev, "description": desc, "url": url, "iocs": iocs}
        r = requests.post(hook, json=payload, timeout=15)
        r.raise_for_status()

    def _send_telegram(self, title, desc, sev, iocs, url, text):
        r = requests.post(f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage",
                          json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": text[:4000],
                                "disable_web_page_preview": True}, timeout=15)
        r.raise_for_status()

    def _send_email(self, title, desc, sev, iocs, url, text):
        msg = EmailMessage()
        msg["Subject"] = f"[DarkWeb Monitor][{sev.upper()}] {title}"[:200]
        msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
        msg["To"] = ", ".join(settings.list_of("SMTP_TO"))
        msg.set_content(text)
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as s:
            s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.send_message(msg)
