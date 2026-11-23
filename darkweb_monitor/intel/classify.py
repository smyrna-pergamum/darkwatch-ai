"""Threat classification: maps an alert / page to a DarkWatch threat class.

Hybrid: the local AI page category (when available) is one signal among
deterministic keyword signals, IOC types and the alert source. Every result
lists the signals that produced it, so analysts can see *why*."""
from __future__ import annotations

import re
from dataclasses import dataclass

# class -> (label, base weight used by risk scoring, MITRE ATT&CK / context hint)
THREAT_CLASSES: dict[str, tuple[str, int, str]] = {
    "ransomware": ("Ransomware / extortion", 30, "T1486 Data Encrypted for Impact, T1657 Financial Theft"),
    "initial_access": ("Initial access sale", 28, "T1078 Valid Accounts, T1133 External Remote Services"),
    "credential_leak": ("Credential leak", 22, "T1078 Valid Accounts, T1589.001 Credentials"),
    "data_breach": ("Data breach / data sale", 22, "T1567 Exfiltration Over Web Service"),
    "insider": ("Insider recruitment", 20, "T1199 Trusted Relationship"),
    "exploit": ("Exploit / vulnerability trade", 18, "T1190 Exploit Public-Facing Application"),
    "malware": ("Malware / stealer logs", 18, "T1555 Credentials from Password Stores"),
    "phishing": ("Phishing kit / brand abuse", 15, "T1566 Phishing, T1583.001 Domains"),
    "fraud": ("Fraud / carding", 12, "T1657 Financial Theft"),
    "doxxing": ("Doxxing / executive exposure", 12, "T1589 Gather Victim Identity Information"),
    "ddos": ("DDoS threat", 10, "T1498 Network Denial of Service"),
    "mention": ("Brand / asset mention", 4, ""),
}

_SIGNALS: dict[str, list[str]] = {
    "ransomware": [r"ransom", r"leak ?site", r"\bdecrypt(or|ion)\b", r"\bencrypted\b.*files", r"countdown",
                   r"\bpublish(ed)? in \d+ days\b", r"\blockbit\b", r"\bblackcat\b|\balphv\b", r"\bclop\b|\bcl0p\b",
                   r"\bakira\b", r"\bplay ?news\b", r"\bblack ?basta\b", r"\brhysida\b", r"\bmedusa\b", r"extortion"],
    "initial_access": [r"initial access", r"\b(rdp|vpn|citrix|fortinet|pulse ?secure|ssh) access\b",
                       r"\bdomain admin\b", r"\bwebshell\b", r"\bIAB\b", r"access to (the )?network", r"\bvpn creds\b",
                       r"\b(revenue|rev)\s*[:$]"],
    "credential_leak": [r"combo ?list", r"\bcredentials?\b", r"\bpasswords?\b", r"email:pass", r"\bcreds\b",
                        r"\blogins?\b dump", r"\baccounts? leak"],
    "data_breach": [r"\bdatabase\b", r"\bdb dump\b", r"\bdump\b", r"\bleak(ed)?\b", r"\bbreach\b", r"\bselling\b.*data",
                    r"\brecords\b", r"\bcustomers? data\b", r"\bsql\b dump", r"\bGB of\b"],
    "insider": [r"\binsiders?\b", r"looking for (employees|staff)", r"work(ing)? (at|for) .* (pay|reward)",
                r"\bemployee wanted\b"],
    "exploit": [r"\bCVE-\d{4}-\d+", r"\b0-?day\b", r"\bzero[- ]day\b", r"\bexploit\b", r"\bRCE\b", r"\bPoC\b"],
    "malware": [r"\bstealer\b", r"\bredline\b", r"\braccoon\b", r"\blumma\b", r"\bvidar\b", r"\bbotnet\b",
                r"\bloader\b", r"\bRAT\b", r"\bcrypter\b", r"\blogs? (cloud|shop)\b"],
    "phishing": [r"\bphish", r"\bscam ?page\b", r"\bfake (login|site)\b", r"\bkit\b.*login", r"\b2fa bypass\b",
                 r"\bevilginx\b", r"\blookalike\b"],
    "fraud": [r"\bcarding\b", r"\bcvv\b", r"\bfullz\b", r"\bdumps? with pin\b", r"\bbank logs?\b", r"\bcashout\b",
              r"\bgift ?cards?\b"],
    "doxxing": [r"\bdox", r"\bhome address\b", r"\bpersonal (info|data) of\b", r"\bSSN\b", r"\bpassport (scan|copy)\b"],
    "ddos": [r"\bddos\b", r"\bbooter\b", r"\bstresser\b", r"\btake (it|them) down\b"],
}
_COMPILED = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in _SIGNALS.items()}

# AI page category (see ai/prompts.py) -> threat class hint
_AI_CATEGORY = {"ransomware": "ransomware", "credentials": "credential_leak", "leak_site": "data_breach",
                "carding": "fraud", "fraud": "fraud", "hacking": "exploit", "marketplace": "data_breach"}
# alert source -> threat class hint
_SOURCE = {"ransomware": "ransomware", "hibp": "credential_leak", "intelx": "data_breach"}
# IOC type -> class hint
_IOC = {"credential": "credential_leak", "cve": "exploit"}


@dataclass(frozen=True)
class Classification:
    threat_class: str
    label: str
    confidence: float
    signals: tuple[str, ...]
    mitre: str

    def as_dict(self) -> dict:
        return {"threat_class": self.threat_class, "label": self.label, "confidence": round(self.confidence, 2),
                "signals": list(self.signals), "mitre": self.mitre}


def classify(text: str = "", *, source: str = "", ai_category: str = "",
             ioc_types: list[str] | None = None) -> Classification:
    """Score every class and return the best one (``mention`` when nothing fires)."""
    scores: dict[str, float] = {}
    signals: dict[str, list[str]] = {}

    def add(cls: str, pts: float, why: str) -> None:
        scores[cls] = scores.get(cls, 0.0) + pts
        signals.setdefault(cls, []).append(why)

    sample = (text or "")[:20000]
    for cls, pats in _COMPILED.items():
        for p in pats:
            m = p.search(sample)
            if m:
                add(cls, 1.0, f"text: '{m.group(0)[:40]}'")
    if source in _SOURCE:
        add(_SOURCE[source], 3.0, f"source: {source}")
    if ai_category in _AI_CATEGORY:
        add(_AI_CATEGORY[ai_category], 2.0, f"AI category: {ai_category}")
    for it in set(ioc_types or []):
        base = it.split(":", 1)[-1]
        if base in _IOC:
            add(_IOC[base], 1.5, f"indicator: {base}")
    if not scores:
        return Classification("mention", THREAT_CLASSES["mention"][0], 0.3, ("no threat signals",), "")
    # tie-break by class weight: a ransomware post that also says "database" stays ransomware
    best = max(scores, key=lambda c: (scores[c], THREAT_CLASSES[c][1]))
    total = sum(scores.values())
    conf = min(0.95, 0.35 + 0.15 * scores[best] + 0.2 * (scores[best] / total))
    label, _, mitre = THREAT_CLASSES[best]
    return Classification(best, label, conf, tuple(signals[best][:6]), mitre)


def class_weight(threat_class: str) -> int:
    return THREAT_CLASSES.get(threat_class, THREAT_CLASSES["mention"])[1]
