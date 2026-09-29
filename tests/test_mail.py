"""Offline tests for the email parsers. Run with:  python -m pytest"""

from sme_scan.checks.mail import (
    classify_mx, count_spf_lookups, is_dkim_key, parse_dmarc, parse_spf, verdict,
)
from sme_scan.scan import clean_domain


# --- DMARC ---

def test_dmarc_full_record():
    r = parse_dmarc(["v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:d@x.ch"])
    assert r["dmarc_policy"] == "reject"
    assert r["dmarc_sp"] == "none"
    assert r["dmarc_pct"] == 50
    assert r["dmarc_rua"] is True
    assert r["dmarc_ruf"] is False


def test_dmarc_sp_inherits_p_and_pct_defaults_to_100():
    r = parse_dmarc(["v=DMARC1;p=quarantine"])  # no spaces is valid too
    assert r["dmarc_sp"] == "quarantine"
    assert r["dmarc_pct"] == 100


def test_dmarc_ignores_unrelated_txt_and_case():
    r = parse_dmarc(["google-site-verification=abc", "V=dmarc1; P=REJECT"])
    assert r["dmarc_policy"] == "reject"


def test_dmarc_missing_p_is_malformed():
    assert parse_dmarc(["v=DMARC1; rua=mailto:a@b.ch"])["dmarc_policy"] == "malformed"


def test_dmarc_multiple_records():
    r = parse_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert r["dmarc_policy"] == "multiple records"


def test_no_dmarc():
    assert parse_dmarc([])["dmarc_policy"] == ""


# --- verdict ---

def test_verdicts():
    assert verdict("", "") == "no DMARC"
    assert verdict("none", 100) == "DMARC but no enforcement"
    assert verdict("reject", 100) == "protected"
    assert verdict("quarantine", 25) == "partial enforcement"
    assert verdict("reject", 0) == "DMARC but no enforcement"
    assert verdict("multiple records", "") == "DMARC but no enforcement"


# --- SPF ---

def test_spf_qualifiers():
    assert parse_spf(["v=spf1 mx -all"])["spf_all"] == "hard fail"
    assert parse_spf(["v=spf1 mx ~all"])["spf_all"] == "soft fail"
    assert parse_spf(["v=spf1 mx all"])["spf_all"] == "pass all (ineffective)"
    assert parse_spf(["v=spf1 redirect=_spf.x.ch"])["spf_all"] == "redirect"
    assert parse_spf(["v=spf1 mx"])["spf_all"] == "no all mechanism"


def test_spf10_is_not_spf():
    assert parse_spf(["v=spf10 -all"])["spf_record"] == ""


def test_spf_multiple_records():
    assert parse_spf(["v=spf1 -all", "v=spf1 mx -all"])["spf_all"] == "multiple records"


def fake_dns(records):
    """A stand-in for DNS: a dict of name -> TXT records."""
    return lambda name: records.get(name, [])


def test_spf_lookup_count_follows_includes():
    dns = fake_dns({
        "firma.ch": ["v=spf1 mx a include:spf.hoster.ch ip4:1.2.3.4 -all"],  # mx, a, include = 3
        "spf.hoster.ch": ["v=spf1 include:_a.hoster.ch include:_b.hoster.ch ~all"],  # 2
        "_a.hoster.ch": ["v=spf1 ip4:10.0.0.0/8 -all"],  # 0
        "_b.hoster.ch": ["v=spf1 a:mx.hoster.ch -all"],  # 1
    })
    assert count_spf_lookups("firma.ch", dns) == 6


def test_spf_lookup_count_survives_include_loop():
    dns = fake_dns({
        "a.ch": ["v=spf1 include:b.ch -all"],
        "b.ch": ["v=spf1 include:a.ch -all"],
    })
    assert count_spf_lookups("a.ch", dns) == 2  # each include costs 1, then the loop stops


# --- DKIM ---

def test_dkim_key_detection():
    assert is_dkim_key("v=DKIM1; k=rsa; p=MIIBIjANBg...")
    assert not is_dkim_key("v=DKIM1; p=")                 # revoked key
    assert not is_dkim_key("v=spf1 include:x.ch -all")    # wildcard noise


# --- MX provider ---

def test_classify_mx_known_providers():
    assert classify_mx("firma.ch", ["firma-ch.mail.protection.outlook.com"]) == ("Microsoft 365", "cloud suite")
    assert classify_mx("firma.ch", ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]) == ("Google Workspace", "cloud suite")
    assert classify_mx("firma.ch", ["mx01.hornetsecurity.com"]) == ("Hornetsecurity", "gateway")


def test_classify_mx_no_mail():
    assert classify_mx("firma.ch", []) == ("no MX", "none")
    assert classify_mx("firma.ch", [""]) == ("null MX", "none")


def test_classify_mx_unknown_shows_base_domain():
    assert classify_mx("firma.ch", ["mx2.somehoster.ch"]) == ("somehoster.ch", "unknown")
    # suffix matching must respect label boundaries
    assert classify_mx("firma.ch", ["evilgoogle.com"]) == ("evilgoogle.com", "unknown")


def test_classify_mx_own_name_resolved_via_ptr():
    mx = ["mail.firma.ch"]
    assert classify_mx("firma.ch", mx, "srv42.hostpoint.ch") == ("Hostpoint", "hoster")
    assert classify_mx("firma.ch", mx, "static.1.2.3.4.somehoster.ch") == ("somehoster.ch", "unknown")
    assert classify_mx("firma.ch", mx, "mail.firma.ch") == ("self-hosted", "self-hosted")
    assert classify_mx("firma.ch", mx, "") == ("self-hosted", "self-hosted")


# --- domain cleanup ---

def test_clean_domain():
    assert clean_domain("https://www.example.ch/kontakt") == "example.ch"
    assert clean_domain("example.ch") == "example.ch"
    assert clean_domain("http://shop.example.ch:8080") == "shop.example.ch"
    assert clean_domain("not found") is None
    assert clean_domain("") is None
