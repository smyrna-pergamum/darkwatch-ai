"""Prompt templates for AI analysis."""
from __future__ import annotations

SYSTEM_ANALYST = (
    "You are a defensive cyber-threat intelligence analyst. "
    "You analyze content collected from the Tor/dark web for authorized monitoring. "
    "Extract IOCs, summarize, assess severity (low/medium/high/critical) and category. "
    "Never provide operational guidance for attacks. Output JSON when asked."
)

PROMPT_SUMMARY = """Analyze the following dark-web page content.

URL: {url}
TITLE: {title}

CONTENT (truncated):
{content}

Return a JSON object with keys:
- "summary": 2-4 sentence summary of what the page is about
- "category": one of [marketplace, forum, leak, ransomware, carding, drugs, weapons, fraud, hacking, other, unknown]
- "severity": one of [low, medium, high, critical] based on threat to monitored assets
- "keywords_found": list of notable keywords/phrases
- "ioc_hints": list of suspicious indicators mentioned (not structured)
Return ONLY valid JSON."""

PROMPT_IOC = """Extract structured indicators of compromise (IOCs) from the text.

TEXT:
{content}

Return a JSON array of objects with keys: type (ip|email|hash|url|domain|crypto|other), value, confidence (0.0-1.0).
Only include real indicators, not generic words. Return ONLY a JSON array."""

PROMPT_TRIAGE = """You are triaging an alert for a SOC.

Alert title: {title}
Severity: {severity}
Description: {description}
Related IOCs: {iocs}

Decide: is this a true positive worth escalating? Reply JSON:
{{"true_positive": bool, "escalate": bool, "reason": "short reason", "recommended_action": "short action"}}"""

PROMPT_RUN_SUMMARY = """You are a SOC analyst writing a post-crawl assessment of a dark-web monitoring run.

START URL: {url}
PAGES CRAWLED: {pages}
IOCS FOUND: {iocs}
ALERTS RAISED: {alerts}
ALERT SEVERITIES: {sev_counts}
IOC TYPES: {ioc_types}
WATCHED KEYWORDS: {keywords}

PAGE SUMMARIES:
{page_summaries}

Write a concise executive summary of what this run found and what it means for a defender.
Return ONLY valid JSON with keys:
- "summary": 3-6 sentence executive summary
- "risk_level": one of [low, medium, high, critical]
- "key_findings": short list of the most important findings
- "recommendations": short list of concrete next steps for the SOC
Be factual; do not invent indicators or pages that are not listed above."""