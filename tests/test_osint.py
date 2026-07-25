"""Offline tests for the OSINT Toolkit."""

from osint import dns_recon, whois_intel, username_check


def test_dns_name_encode_read_roundtrip():
    enc = dns_recon._encode_name("www.example.com")
    name, end = dns_recon._read_name(enc, 0)
    assert name == "www.example.com"
    assert end == len(enc)


def test_dns_rtypes_known():
    assert dns_recon.RTYPES["A"] == 1 and dns_recon.RTYPES["MX"] == 15


def test_whois_summary_parser():
    sample = "Registrar: Example Registrar\nCreation Date: 2020-01-01\nCountry: US"
    s = whois_intel._summarize(sample)
    assert s.get("registrar") == "Example Registrar" and s.get("country") == "US"


def test_whois_routes_ip_vs_domain(monkeypatch):
    calls = {}
    monkeypatch.setattr(whois_intel, "whois_ip", lambda t, **k: calls.setdefault("ip", t))
    monkeypatch.setattr(whois_intel, "whois_domain", lambda t, **k: calls.setdefault("dom", t))
    whois_intel.lookup("8.8.8.8")
    whois_intel.lookup("example.com")
    assert calls.get("ip") == "8.8.8.8" and calls.get("dom") == "example.com"


def test_username_sites_are_templates():
    assert len(username_check.SITES) >= 10
    assert all("{}" in url for url in username_check.SITES.values())
