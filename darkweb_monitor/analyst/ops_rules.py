"""Rule-based planner for the operator agent: used when no AI model is
available. Understands simple Turkish / English requests well enough to run
the right tools, and writes a plain summary of what came back."""
from __future__ import annotations

import re

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_ONION = re.compile(r"(?:https?://)?[a-z2-7]{56}\.onion\S*", re.I)
_DOMAIN = re.compile(r"(?<![@\w.-])(?:[a-z0-9-]+\.)+(?:com\.tr|org\.tr|com|net|org|io|de|tr|gov|edu|co|uk|eu|info|biz|app|dev|ai|"
                     r"fr|nl|it|es|ch|at|us|ru|cn|in|br|jp|be|se|no|dk|fi|pl|cz|gr|pt|ie|ca|au)\b", re.I)
_QUOTED = re.compile(r"[\"“”'‘’«»]([^\"“”'‘’«»]{2,80})[\"“”'‘’«»]")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

ONION_WORDS = ("onion", "ahmia", "tor ", "dark web", "darkweb", "darknet", "hidden service", "gizli servis",
               "karanlık ağ", "torch", "haystak")
MONITOR_WORDS = {"hourly": ("her saat", "saatlik", "hourly", "every hour"),
                 "6h": ("6 saatte", "every 6 hours", "6h"),
                 "12h": ("12 saatte", "günde iki", "twice a day", "every 12 hours"),
                 "weekly": ("her hafta", "haftalık", "weekly", "every week"),
                 "daily": ("her gün", "günlük", "daily", "every day", "izle", "takip et", "monitor", "watch for",
                           "sürekli", "düzenli")}
CRAWL_WORDS = ("crawl", "tara ", "taramasını", "tarat", "scan ")
SOURCE_ALIASES = {"hibp": "hibp", "have i been pwned": "hibp", "intelx": "intelx", "intelligence x": "intelx",
                  "ransomware": "ransomware", "fidye": "ransomware", "ahmia": "ahmia", "hudson": "hudsonrock",
                  "infostealer": "hudsonrock", "stealer": "hudsonrock", "leakcheck": "leakcheck",
                  "dehashed": "dehashed", "crt.sh": "crtsh", "sertifika": "crtsh", "certificate": "crtsh",
                  "phishing": "crtsh", "oltalama": "crtsh", "urlscan": "urlscan", "paste": "psbdmp",
                  "pastebin": "psbdmp", "leakix": "leakix", "shodan": "shodan", "github": "github"}


def request_part(text: str) -> str:
    return text.split("\n\n[Context]")[0].split("\n[Context]")[0]


def extract_terms(text: str) -> list[str]:
    t = request_part(text)
    terms: list[str] = []
    for rx in (_EMAIL, _IP):
        terms += rx.findall(t)
    no_mail = _EMAIL.sub(" ", _ONION.sub(" ", t))
    terms += [m.group(0) for m in _DOMAIN.finditer(no_mail)]
    terms += [q.strip() for q in _QUOTED.findall(t)]
    out = []
    for x in terms:
        x = x.strip().strip(".,;:")
        if x and x.lower() not in [o.lower() for o in out]:
            out.append(x)
    return out[:6]


def interval_of(text: str) -> str | None:
    low = " " + request_part(text).lower() + " "
    for every, words in MONITOR_WORDS.items():
        if any(w in low for w in words):
            return every
    return None


def plan(text: str) -> list[dict]:
    req = request_part(text)
    low = " " + req.lower() + " "
    mission_run = "[Scheduled run of mission" in text
    terms = extract_terms(text)
    onions = [o for o in _ONION.findall(req)]
    calls: list[dict] = []
    n = 0

    def add(name, args):
        nonlocal n
        n += 1
        calls.append({"id": f"op{n}", "name": name, "args": args})

    for o in onions[:3]:
        add("crawl_target", {"url": o if o.startswith("http") else "http://" + o})
    if onions and not terms:
        return calls
    if any(w in low for w in CRAWL_WORDS) and not onions:
        add("list_targets", {})
    if not terms:
        if not calls:
            add("list_sources", {})
        return calls
    wanted = sorted({v for k, v in SOURCE_ALIASES.items() if k in low})
    if any(w in low for w in ONION_WORDS):
        for t in terms[:3]:
            add("search_onions", {"query": t})
        wanted = [w for w in wanted if w != "ahmia"]
        if wanted:
            add("query_sources", {"terms": terms, "sources": wanted})
    else:
        add("query_sources", {"terms": terms, **({"sources": wanted} if wanted else {})})
    add("search", {"query": terms[0][:200], "limit": 8})
    every = interval_of(text)
    if every and not mission_run:
        add("create_mission", {"instruction": req.strip()[:2000], "every": every})
    return calls


def _fmt_query(res: dict) -> list[str]:
    lines = []
    for r in res.get("results") or []:
        f = r.get("findings") or []
        if r.get("status") == "skipped":
            lines.append(f"- {r.get('label') or r['source']}: skipped ({r.get('error')})")
        elif r.get("status") == "failed":
            lines.append(f"- {r.get('label') or r['source']}: FAILED - {r.get('error')}")
        else:
            lines.append(f"- {r.get('label') or r['source']}: {len(f)} finding(s)")
            lines += [f"    [{x.get('severity')}] {x.get('title')}" for x in f[:5]]
    return lines


def answer(text: str, results: dict) -> str:
    out = []
    if not results:
        return ("I could not find anything searchable in the request. Give me a domain, e-mail, brand in quotes or "
                "an .onion address - e.g. 'acme.com için tüm kaynaklarda sızıntı ara' or "
                "'Ahmia'da \"Acme Corp\" geçen onion siteleri bul'.\n"
                "(Rule-based mode - set up an AI model under AI & Models for free-form conversations.)")
    for res in results.get("query_sources", []):
        if "results" in res:
            terms = ", ".join(t["value"] for t in res.get("terms", []))
            out.append(f"Intel sources for {terms}" + (" (stored as alerts)" if res.get("saved_as_alerts") else "") + ":")
            out += _fmt_query(res)
        else:
            out.append(f"Intel sources: {res.get('message') or res.get('error') or res}")
    for res in results.get("search_onions", []):
        if "results" not in res:
            out.append(f"Onion search failed: {res.get('message') or res}")
            continue
        items = res["results"]
        out.append(f"Onion search '{res['query']}': {len(items)} site(s)")
        out += [f"- {x['onion']} [{', '.join(x.get('found_by', []))}]{(' - ' + x['title']) if x.get('title') else ''}"
                for x in items[:10]]
        for k, v in (res.get("errors") or {}).items():
            out.append(f"  ({k}: {v})")
        if items:
            out.append("  To monitor one of them, ask me to crawl it - it is proposed as a target for your approval.")
    for res in results.get("search", []):
        if isinstance(res, dict):
            a, p = res.get("alerts") or [], res.get("pages") or []
            out.append(f"Already collected: {len(a)} alert(s), {len(p)} page(s)")
            out += [f"- alert #{x['id']} [{x['severity']}] {x['title']}" for x in a[:5]]
    for res in results.get("crawl_target", []):
        out.append(f"Crawl: {res.get('message') or res}")
    for res in results.get("list_targets", []):
        if isinstance(res, list):
            out.append("Targets: " + (", ".join(f"#{t['id']} {t['label'] or t['url']}" for t in res[:10]) or "none")
                       + ". Tell me which one to crawl (e.g. 'crawl target 2').")
    for res in results.get("create_mission", []):
        out.append(f"Monitoring mission: {res.get('message') or res.get('status') or res}"
                   + (f" (task #{res['task_id']} in AI Tasks)" if res.get("task_id") else ""))
    for res in results.get("list_sources", []):
        if isinstance(res, list):
            on = [s["label"] for s in res if s.get("enabled")]
            off = [s["label"] for s in res if not s.get("enabled")]
            out.append("Configured sources: " + (", ".join(on) or "none"))
            out.append("Not configured: " + (", ".join(off) or "-") + " (Intel sources → Configure)")
            out.append("Tell me what to look for: a domain, e-mail, brand in quotes or an .onion address.")
    out.append("\n(Rule-based mode - set up an AI model under AI & Models for smarter conversations.)")
    return "\n".join(out)
