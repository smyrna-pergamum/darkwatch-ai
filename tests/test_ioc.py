from darkweb_monitor.ioc.extractor import content_hash, defang, extract, mask_credentials


def types(text):
    return {(r["ioc_type"], r["value"]) for r in extract(text)}


def test_basic_types():
    t = types("mail bob@corp-x.de from 8.8.8.8 md5 9e107d9d372bb6826bd81d3542a419d6 CVE-2023-4966")
    assert ("email", "bob@corp-x.de") in t
    assert ("ip", "8.8.8.8") in t
    assert ("md5", "9e107d9d372bb6826bd81d3542a419d6") in t
    assert ("cve", "CVE-2023-4966") in t


def test_ip_false_positives_filtered():
    t = types("bind 0.0.0.0 and 127.0.0.1, firmware version 1.2.3.4, v2.0.0.1")
    assert not any(k == "ip" for k, _ in t)


def test_btc_checksum_validation():
    good = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    bad = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
    bech = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    t = types(f"{good} {bad} {bech}")
    assert ("btc", good) in t
    assert ("btc", bad) not in t
    assert ("btc", bech) in t


def test_onion_v3_only():
    v3 = "a" * 56 + ".onion"
    t = types(f"old abcdefghijklmnop.onion new {v3}")
    assert ("onion", v3) in t
    assert not any(v == "abcdefghijklmnop.onion" for _, v in t)


def test_credentials_never_store_password():
    res = extract("dump: jane@corp.com:Sup3rSecret! end")
    cred = [r for r in res if r["ioc_type"] == "credential"]
    assert cred and "Sup3rSecret" not in cred[0]["value"] and "Sup3rSecret" not in cred[0]["context"]
    assert cred[0]["value"].startswith("jane@corp.com:S")
    assert "Sup3rSecret" not in mask_credentials("jane@corp.com:Sup3rSecret! end")


def test_example_domains_ignored_and_dedup():
    res = extract("a@example.com b@real.org b@real.org")
    emails = [r["value"] for r in res if r["ioc_type"] == "email"]
    assert emails == ["b@real.org"]


def test_helpers():
    assert len(content_hash("x")) == 64
    assert defang("http://x.onion/") == "hxxp://x[.]onion/"
