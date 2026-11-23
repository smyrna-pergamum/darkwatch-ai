import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from darkweb_monitor.ioc.extractor import extract, content_hash


def test_email_ip():
    text = "Contact admin@example.com from 192.168.1.10 leak md5 d41d8cd98f00b204e9800998ecf8427e"
    res = extract(text)
    types = {r["ioc_type"] for r in res}
    assert "email" in types
    assert "ip" in types
    assert "md5" in types


def test_onion():
    text = "Visit abcdefghijklmnop.onion for more"
    res = extract(text)
    assert any(r["ioc_type"] == "onion" for r in res)


def test_hash():
    h = content_hash("hello")
    assert len(h) == 64