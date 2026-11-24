"""Public threat feeds (cached locally) and on-demand indicator enrichment.

Feeds:  CISA KEV (actively exploited CVEs), Feodo Tracker (botnet C2 IPs).
Lookups (keys required): VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox.
Feeds are used to *validate and correlate* what the crawler finds."""
from __future__ import annotations

import base64
import logging

import requests

from config.settings import settings
from .. import __version__
from ..storage.db import session_scope
from ..storage.models import FeedEntry, Indicator, utcnow

logger = logging.getLogger(__name__)
FEED_TAG = {"kev": "kev-exploited", "feodo": "feodo-c2"}


def _http() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = f"darkwatch-ai/{__version__}"
    return s


def _store(feed: str, rows: list[tuple[str, str, dict]]) -> int:
    with session_scope() as s:
        existing = {e.value: e for e in s.query(FeedEntry).filter_by(feed=feed)}
        for ioc_type, value, info in rows:
            e = existing.get(value)
            if e:
                e.info, e.updated_at = info, utcnow()
            else:
                s.add(FeedEntry(feed=feed, ioc_type=ioc_type, value=value, info=info))
    return len(rows)


def refresh_feeds() -> dict:
    out = {}
    http = _http()
    try:
        data = http.get(settings.CISA_KEV_URL, timeout=60).json()
        rows = [("cve", v["cveID"].upper(), {
            "vendor": v.get("vendorProject"), "product": v.get("product"),
            "name": v.get("vulnerabilityName"), "added": v.get("dateAdded"),
            "ransomware": v.get("knownRansomwareCampaignUse")}) for v in data.get("vulnerabilities", [])]
        out["kev"] = _store("kev", rows)
    except Exception as e:  # noqa: BLE001
        out["kev"] = f"error: {e}"
    try:
        data = http.get(settings.FEODO_URL, timeout=60).json()
        rows = [("ip", v["ip_address"], {"port": v.get("port"), "malware": v.get("malware"),
                                         "status": v.get("status"), "last_online": v.get("last_online"),
                                         "country": v.get("country")}) for v in data if v.get("ip_address")]
        out["feodo"] = _store("feodo", rows)
    except Exception as e:  # noqa: BLE001
        out["feodo"] = f"error: {e}"
    out["tagged"] = tag_indicators()
    return out


def feed_tags_for(s, ioc_type: str, value: str) -> list[str]:
    v = value.upper() if ioc_type == "cve" else value
    return [FEED_TAG.get(e.feed, e.feed) for e in s.query(FeedEntry).filter_by(value=v)]


def tag_indicators() -> int:
    n = 0
    with session_scope() as s:
        feed_vals = {(e.value): e.feed for e in s.query(FeedEntry).all()}
        for ind in s.query(Indicator).filter(Indicator.ioc_type.in_(("cve", "ip", "ai:cve", "ai:ip"))):
            feed = feed_vals.get(ind.value.upper() if "cve" in ind.ioc_type else ind.value)
            if feed:
                tag = FEED_TAG.get(feed, feed)
                tags = set(filter(None, (ind.tags or "").split(",")))
                if tag not in tags:
                    tags.add(tag)
                    ind.tags = ",".join(sorted(tags))
                    n += 1
    return n


# --------------------------------------------------------------------- lookups
def _vt(ioc_type: str, value: str):
    if not settings.VIRUSTOTAL_API_KEY:
        return None
    kind = {"ip": "ip_addresses", "url": "urls", "md5": "files", "sha1": "files",
            "sha256": "files", "domain": "domains"}.get(ioc_type)
    if not kind:
        return None
    ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if kind == "urls" else value
    r = _http().get(f"https://www.virustotal.com/api/v3/{kind}/{ident}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=30)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"found": True, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)}


def _abuseipdb(ioc_type: str, value: str):
    if ioc_type != "ip" or not settings.ABUSEIPDB_API_KEY:
        return None
    r = _http().get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": value, "maxAgeInDays": 90},
                    headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}, timeout=30)
    r.raise_for_status()
    d = r.json().get("data", {})
    return {"abuse_score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"),
            "country": d.get("countryCode"), "isp": d.get("isp")}


def _otx(ioc_type: str, value: str):
    if not settings.OTX_API_KEY:
        return None
    sect = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file",
            "sha256": "file", "cve": "cve"}.get(ioc_type)
    if not sect:
        return None
    r = _http().get(f"https://otx.alienvault.com/api/v1/indicators/{sect}/{value}/general",
                    headers={"X-OTX-API-KEY": settings.OTX_API_KEY}, timeout=30)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    pi = r.json().get("pulse_info", {})
    return {"pulses": pi.get("count", 0), "names": [p.get("name") for p in pi.get("pulses", [])[:5]]}


def _threatfox(ioc_type: str, value: str):
    if not settings.ABUSECH_AUTH_KEY or ioc_type not in ("ip", "url", "domain", "md5", "sha256"):
        return None
    r = _http().post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": value},
                     headers={"Auth-Key": settings.ABUSECH_AUTH_KEY}, timeout=30)
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") != "ok":
        return {"found": False}
    return {"found": True, "malware": sorted({x.get("malware_printable") for x in d.get("data", [])})[:5]}


def _greynoise(ioc_type: str, value: str):
    if ioc_type != "ip" or not settings.GREYNOISE_API_KEY:
        return None
    r = _http().get(f"https://api.greynoise.io/v3/community/{value}", headers={"key": settings.GREYNOISE_API_KEY},
                    timeout=30)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    d = r.json()
    return {"noise": d.get("noise"), "riot": d.get("riot"), "classification": d.get("classification"),
            "name": d.get("name")}


def enrich(ioc_type: str, value: str) -> dict:
    base_type = ioc_type.split(":", 1)[-1]
    out = {}
    with session_scope() as s:
        out["feeds"] = [{"feed": e.feed, "info": e.info} for e in s.query(FeedEntry).filter_by(
            value=value.upper() if base_type == "cve" else value)]
    for name, fn in (("virustotal", _vt), ("abuseipdb", _abuseipdb), ("otx", _otx), ("threatfox", _threatfox),
                     ("greynoise", _greynoise)):
        try:
            res = fn(base_type, value)
            if res is not None:
                out[name] = res
        except Exception as e:  # noqa: BLE001
            out[name] = {"error": str(e)[:200]}
    return out


def lookup_services() -> list[str]:
    return [n for n, k in (("virustotal", settings.VIRUSTOTAL_API_KEY), ("abuseipdb", settings.ABUSEIPDB_API_KEY),
                           ("otx", settings.OTX_API_KEY), ("threatfox", settings.ABUSECH_AUTH_KEY),
                           ("greynoise", settings.GREYNOISE_API_KEY)) if k]
