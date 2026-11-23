from darkweb_monitor.crawler import parsers
from darkweb_monitor.watchlist import WatchTerm, match, validate
from config.settings import settings
from conftest import ONION_A, ONION_B


def test_domain_matches_subdomains_and_emails():
    terms = [WatchTerm("domain", "acme.com", "high")]
    assert match("leak of vpn.acme.com creds", terms)
    assert match("contact ceo@acme.com", terms)
    assert not match("notacme.com is different", terms)


def test_keyword_word_boundary_and_regex():
    terms = [WatchTerm("keyword", "phoenix"), WatchTerm("regex", r"acme[-_ ]?corp")]
    hits = match("Project Phoenix leaked by ACME_Corp", terms)
    assert {h["value"] for h in hits} == {"phoenix", r"acme[-_ ]?corp"}
    assert not match("phoenixes", [WatchTerm("keyword", "phoenix")])


def test_validate():
    assert validate("keyword", "ab")
    assert validate("regex", "([")
    assert validate("nope", "x")
    assert validate("domain", "acme.com") is None


def test_scope(monkeypatch):
    start = f"http://{ONION_A}/"
    assert parsers.in_scope(f"http://{ONION_A}/x", start)
    assert not parsers.in_scope(f"http://{ONION_B}/", start)  # same_site default
    assert parsers.in_scope(f"http://{ONION_B}/", start, "any_onion")
    assert not parsers.in_scope("http://clearnet.com/", start, "any_onion")
    assert not parsers.in_scope(f"http://{ONION_A}/file.zip", start)
    monkeypatch.setattr(settings, "ALLOWED_DOMAINS", ONION_B)
    assert parsers.in_scope(f"http://{ONION_B}/", start, "allowed")


def test_normalize_and_parse():
    assert parsers.normalize_url("HTTP://X.onion:80/a#frag") == "http://x.onion/a"
    p = parsers.parse_page('<title>T</title><script>evil()</script><a href="/b">Next page</a>', "http://x.onion/a")
    assert p["title"] == "T" and "evil" not in p["text"]
    assert p["links"] == [{"url": "http://x.onion/b", "text": "Next page"}]


def test_safety_filter():
    assert parsers.safety_violation("cp links here")
    assert parsers.safety_violation("normal forum") is None
