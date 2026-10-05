"""Offline tests for the email parsers. Run with:  python -m pytest"""

import pytest

from sme_scan.checks.mail import (
    SPF_LOOKUP_LIMIT, classify_mx, count_spf_lookups, effective_policy, is_dkim_key,
    parse_dmarc, parse_spf, step_down, verdict,
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


def test_dmarc_t_tag():
    assert parse_dmarc(["v=DMARC1; p=reject; t=y"])["dmarc_t"] == "y"
    assert parse_dmarc(["v=DMARC1; p=reject; T=Y"])["dmarc_t"] == "y"
    assert parse_dmarc(["v=DMARC1; p=reject"])["dmarc_t"] == "n"         # default
    assert parse_dmarc(["v=DMARC1; p=reject; t=maybe"])["dmarc_t"] == "n"  # invalid -> default


def test_dmarc_obsolete_tags():
    r = parse_dmarc(["v=DMARC1; p=none; pct=100; rf=afrf; ri=86400"])
    assert r["dmarc_obsolete_tags"] == "pct rf ri"
    assert parse_dmarc(["v=DMARC1; p=none; t=y"])["dmarc_obsolete_tags"] == ""


# --- verdict ---

def test_step_down():
    assert step_down("reject") == "quarantine"
    assert step_down("quarantine") == "none"
    assert step_down("none") == "none"


def test_effective_policy_takes_the_weaker_rule_set():
    assert effective_policy("reject", "n", 100) == "reject"
    assert effective_policy("quarantine", "y", 100) == "none"        # RFC 9989 receivers
    assert effective_policy("quarantine", "n", 50) == "none"         # RFC 7489 receivers
    assert effective_policy("reject", "y", 50) == "quarantine"       # both: one level down


# One row per case from the plan: (record, effective policy, verdict)
VERDICT_CASES = [
    ("v=DMARC1; p=reject", "reject", "protected"),
    ("v=DMARC1; p=reject; t=y", "quarantine", "protected"),
    ("v=DMARC1; p=quarantine; t=y", "none", "DMARC but no enforcement"),
    ("v=DMARC1; p=quarantine; t=n", "quarantine", "protected"),
    ("v=DMARC1; p=quarantine; t=maybe", "quarantine", "protected"),
    ("v=DMARC1; p=reject; pct=0", "quarantine", "protected"),
    ("v=DMARC1; p=reject; pct=50", "quarantine", "protected"),
    ("v=DMARC1; p=quarantine; pct=50", "none", "partial enforcement"),
    ("v=DMARC1; p=quarantine; pct=0", "none", "DMARC but no enforcement"),
    ("v=DMARC1; p=reject; t=y; pct=50", "quarantine", "protected"),
    ("v=DMARC1; p=none", "none", "DMARC but no enforcement"),
]


@pytest.mark.parametrize("record, effective, expected", VERDICT_CASES)
def test_verdict_cases(record, effective, expected):
    r = parse_dmarc([record])
    assert effective_policy(r["dmarc_policy"], r["dmarc_t"], r["dmarc_pct"]) == effective
    assert verdict(r["dmarc_policy"], r["dmarc_t"], r["dmarc_pct"]) == expected


def test_verdict_without_a_usable_record():
    assert verdict("", "", "") == "no DMARC"
    assert verdict("multiple records", "", "") == "DMARC but no enforcement"
    assert verdict("malformed", "n", 100) == "DMARC but no enforcement"


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


def test_spf_include_loop_runs_into_the_limit():
    dns = fake_dns({
        "a.ch": ["v=spf1 include:b.ch -all"],
        "b.ch": ["v=spf1 include:a.ch -all"],
    })
    # Receivers have no loop detection: a loop is simply over the limit
    assert count_spf_lookups("a.ch", dns) == SPF_LOOKUP_LIMIT + 1


def test_spf_exactly_at_the_limit_is_still_counted_exactly():
    dns = fake_dns({"firma.ch": ["v=spf1 " + " ".join(f"a:h{i}.firma.ch" for i in range(10)) + " -all"]})
    assert count_spf_lookups("firma.ch", dns) == 10


def test_spf_fan_out_is_bounded():
    # Every name answers with 10 includes of new names (a wildcard record can
    # do this). Without a shared budget this tree would cost billions of lookups.
    queried = []

    def hostile_txt(name):
        queried.append(name)
        return ["v=spf1 " + " ".join(f"include:c{i}.{name}" for i in range(10)) + " -all"]

    assert count_spf_lookups("evil.com", hostile_txt) == SPF_LOOKUP_LIMIT + 1
    assert len(queried) <= SPF_LOOKUP_LIMIT + 1


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
