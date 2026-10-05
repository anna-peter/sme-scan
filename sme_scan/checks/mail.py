"""
Email-authentication checks: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, and
who operates the domain's mail (from its MX records).

(Named mail.py, not email.py: a module called `email` can shadow Python's
standard-library `email` package in some import situations.)

Structure: the parse_* / count_* / classify_* functions are *pure* - they take
strings (or a lookup function) and return values, with no network access. Only
check_mail() talks to DNS. That split is what makes tests/test_mail.py possible.
"""

from __future__ import annotations

import re
from typing import Callable

from sme_scan.dns_utils import LookupFailed, a, mx, ptr, txt

# Output columns, in CSV order. Kept here so the CLI doesn't need to know them.
COLUMNS = [
    "domain",
    "mx_hosts", "mx_ptr", "mail_provider", "provider_type", "accepts_mail",
    "spf_record", "spf_all", "spf_lookups", "spf_too_many_lookups",
    "dmarc_record", "dmarc_policy", "dmarc_sp", "dmarc_pct",
    "dmarc_t", "dmarc_effective_policy", "dmarc_obsolete_tags",
    "dmarc_rua", "dmarc_ruf",
    "dkim_selectors",
    "mta_sts", "tls_rpt", "bimi",
    "verdict", "error",
]

VALID_POLICIES = ("none", "quarantine", "reject")  # weakest to strictest
OBSOLETE_DMARC_TAGS = ("pct", "rf", "ri")  # removed by RFC 9989 (May 2026)
SPF_LOOKUP_LIMIT = 10  # RFC 7208 section 4.6.4


# --- shared helpers ------------------------------------------------------------

def parse_tags(record: str) -> dict[str, str]:
    """Parse 'k=v; k=v' records (DMARC, DKIM, MTA-STS, BIMI all use this format).

    >>> parse_tags("v=DMARC1; p=reject; rua=mailto:a@b.ch")
    {'v': 'DMARC1', 'p': 'reject', 'rua': 'mailto:a@b.ch'}
    """
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)  # split once: values may contain '='
            tags[key.strip().lower()] = value.strip()
    return tags


def starts_with_version(record: str, version: str) -> bool:
    """True if the record begins with e.g. 'v=spf1' (case-insensitive).

    Checks the character after the version too, so 'v=spf10' doesn't count as SPF.
    """
    pattern = rf"^\s*v\s*=\s*{re.escape(version)}(\s|;|$)"
    return re.match(pattern, record, re.I) is not None


# --- DMARC -----------------------------------------------------------------------

def parse_dmarc(records: list[str]) -> dict:
    out = {"dmarc_record": "", "dmarc_policy": "", "dmarc_sp": "",
           "dmarc_pct": "", "dmarc_t": "", "dmarc_obsolete_tags": "",
           "dmarc_rua": False, "dmarc_ruf": False}
    dmarc = [r for r in records if starts_with_version(r, "DMARC1")]
    if not dmarc:
        return out
    if len(dmarc) > 1:
        # RFC 7489 6.6.3 / RFC 9989 4.10: with more than one record, all are
        # discarded, so receivers apply no DMARC at all
        out["dmarc_record"] = " | ".join(dmarc)
        out["dmarc_policy"] = "multiple records"
        return out

    tags = parse_tags(dmarc[0])
    p = tags.get("p", "").lower()
    policy = p if p in VALID_POLICIES else "malformed"
    sp = tags.get("sp", "").lower()

    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100  # an unparseable pct is ignored, so the default applies

    out.update({
        "dmarc_record": dmarc[0],
        "dmarc_policy": policy,
        # sp= is optional; when absent, subdomains inherit p=
        "dmarc_sp": sp if sp in VALID_POLICIES else policy,
        "dmarc_pct": pct,
        # t= (RFC 9989 4.7): "y" means testing. Any other value is invalid and
        # falls back to the default, "n".
        "dmarc_t": "y" if tags.get("t", "").lower() == "y" else "n",
        "dmarc_obsolete_tags": " ".join(t for t in OBSOLETE_DMARC_TAGS if t in tags),
        "dmarc_rua": bool(tags.get("rua")),
        "dmarc_ruf": bool(tags.get("ruf")),
    })
    return out


# --- SPF -------------------------------------------------------------------------

ALL_QUALIFIERS = {
    "-": "hard fail",
    "~": "soft fail",
    "+": "pass all (ineffective)",
    "?": "neutral (ineffective)",
}


def parse_spf(records: list[str]) -> dict:
    out = {"spf_record": "", "spf_all": ""}
    spf = [r for r in records if starts_with_version(r, "spf1")]
    if not spf:
        return out
    if len(spf) > 1:
        # RFC 7208 4.5: multiple SPF records is a permerror, so SPF is effectively broken
        out["spf_record"] = " | ".join(spf)
        out["spf_all"] = "multiple records"
        return out

    record = spf[0]
    out["spf_record"] = record
    m = re.search(r"(?:^|\s)([~\-+?]?)all\b", record, re.I)
    if m:
        # a bare "all" has no qualifier, which means "+" (pass)
        out["spf_all"] = ALL_QUALIFIERS[m.group(1) or "+"]
    elif re.search(r"\bredirect=", record, re.I):
        # the policy lives in another domain's record, e.g. redirect=_spf.provider.ch
        out["spf_all"] = "redirect"
    else:
        out["spf_all"] = "no all mechanism"
    return out


# Mechanisms/modifiers that each trigger a DNS query during SPF evaluation
LOOKUP_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


def count_spf_lookups(domain: str, get_txt: Callable[[str], list[str]],
                      _path: tuple = ()) -> int:
    """How many DNS lookups evaluating this domain's SPF record costs.

    `get_txt` is passed in rather than imported: in production it queries DNS,
    in tests it's a plain dict lookup. (This pattern is "dependency injection".)

    `_path` holds the chain of includes we're inside, to stop include loops.
    """
    if domain in _path or len(_path) > SPF_LOOKUP_LIMIT:
        return 0
    spf = [r for r in get_txt(domain) if starts_with_version(r, "spf1")]
    if len(spf) != 1:
        return 0

    count = 0
    for term in spf[0].split()[1:]:            # [1:] skips "v=spf1"
        term = term.lstrip("+-~?").lower()     # drop the qualifier
        name = re.split(r"[:=/]", term, maxsplit=1)[0]
        if name not in LOOKUP_TERMS:
            continue                           # ip4:, ip6:, all, exp= cost nothing
        count += 1
        if name in ("include", "redirect"):
            target = re.split(r"[:=]", term, maxsplit=1)[1] if re.search(r"[:=]", term) else ""
            if target and "%" not in target:   # skip SPF macros like %{i}
                count += count_spf_lookups(target, get_txt, _path + (domain,))
    return count


# --- DKIM ------------------------------------------------------------------------

# Selector names are chosen by whoever sets up signing, and can't be listed via
# DNS. These are defaults of common providers and tools. Not finding one does
# NOT prove the domain doesn't use DKIM.
COMMON_DKIM_SELECTORS = [
    "selector1", "selector2",            # Microsoft 365
    "google",                            # Google Workspace
    "default", "dkim", "mail", "smtp",   # generic / cPanel / Plesk
    "k1", "k2", "k3",                    # Mailchimp
    "s1", "s2",                          # SendGrid and others
    "key1", "key2", "sig1",              # various (sig1: iCloud)
    "mxvault", "zoho", "zmail",
    "protonmail", "protonmail2", "protonmail3",
    "hs1", "hs2",                        # HubSpot
    "mailjet", "mandrill", "cm",         # Mailjet, Mandrill, Campaign Monitor
]


def is_dkim_key(record: str) -> bool:
    # A real key has a non-empty p= tag. An empty "p=" means the key was revoked.
    # Requiring p= also filters out wildcard TXT records that answer every name.
    return bool(parse_tags(record).get("p"))


# --- mail provider from MX ---------------------------------------------------------

CLOUD, HOSTER, GATEWAY = "cloud suite", "hoster", "gateway"

# (suffix, label, type). Matching is by hostname suffix: "abc.mail.protection.outlook.com"
# ends with "mail.protection.outlook.com". Grown from real scan output; when a
# host isn't listed, its base domain is reported instead, so gaps stay visible.
MX_PROVIDERS = [
    ("mail.protection.outlook.com", "Microsoft 365", CLOUD),
    ("outlook.com", "Microsoft 365", CLOUD),
    ("google.com", "Google Workspace", CLOUD),
    ("googlemail.com", "Google Workspace", CLOUD),
    ("zoho.eu", "Zoho", CLOUD),
    ("zoho.com", "Zoho", CLOUD),
    ("protonmail.ch", "Proton", CLOUD),
    # Swiss hosters / ISPs
    ("infomaniak.ch", "Infomaniak", HOSTER),
    ("hostpoint.ch", "Hostpoint", HOSTER),
    ("cyon.ch", "cyon", HOSTER),
    ("swizzonic.email", "Swizzonic", HOSTER),
    ("swizzonic-mail.ch", "Swizzonic", HOSTER),
    ("hosttech.eu", "hosttech", HOSTER),
    ("hosttech.ch", "hosttech", HOSTER),
    ("hostfactory.ch", "Hostfactory", HOSTER),
    ("iway.ch", "iWay", HOSTER),
    ("vtx.ch", "VTX", HOSTER),
    ("solnet.ch", "Solnet", HOSTER),
    ("netzone.ch", "Netzone", HOSTER),
    ("cyon.net", "cyon", HOSTER),
    ("metanet.ch", "METANET", HOSTER),
    ("ch-meta.net", "METANET", HOSTER),
    ("hoststar.hosting", "Hoststar", HOSTER),
    ("webland.ch", "Webland", HOSTER),
    ("kreativmedia.ch", "kreativmedia.ch", HOSTER),
    ("sui-inter.net", "sui-inter.net", HOSTER),
    ("servicehoster.ch", "servicehoster.ch", HOSTER),
    ("tophost.ch", "tophost.ch", HOSTER),
    ("loginserver.ch", "loginserver.ch", HOSTER),
    ("bluewin.ch", "Swisscom", HOSTER),
    ("swisscom.com", "Swisscom", HOSTER),
    ("swisscom.ch", "Swisscom", HOSTER),
    # International hosters
    ("jimdo.com", "Jimdo", HOSTER),
    ("kundenserver.de", "IONOS", HOSTER),
    ("ionos.de", "IONOS", HOSTER),
    ("one.com", "one.com", HOSTER),
    ("hostinger.com", "Hostinger", HOSTER),
    ("titan.email", "Titan", HOSTER),
    ("ovh.net", "OVH", HOSTER),
    ("rzone.de", "Strato", HOSTER),
    ("gandi.net", "Gandi", HOSTER),
    ("register.it", "Register.it", HOSTER),
    ("mailbox.org", "mailbox.org", HOSTER),
    # Security gateways: filter mail, then forward to the real mailbox provider
    ("seppmail.ch", "SEPPmail", GATEWAY),
    ("seppmail.cloud", "SEPPmail", GATEWAY),
    ("hornetsecurity.com", "Hornetsecurity", GATEWAY),
    ("hornetsecurity.ch", "Hornetsecurity", GATEWAY),
    ("antispameurope.com", "Hornetsecurity", GATEWAY),
    ("antispamcloud.com", "SpamExperts", GATEWAY),
    ("sophos.com", "Sophos", GATEWAY),
    ("pphosted.com", "Proofpoint", GATEWAY),
    ("mimecast.com", "Mimecast", GATEWAY),
    ("iphmx.com", "Cisco", GATEWAY),
    ("barracudanetworks.com", "Barracuda", GATEWAY),
    ("spamcleaner.ch", "Arcade spamcleaner", GATEWAY),
    ("server.devnanotek.com", "DevNanoTek", HOSTER),
]


def base_domain(host: str) -> str:
    """'mx1.mail.hoster.ch' -> 'hoster.ch'.

    Naive (last two labels): fine for .ch/.com/.de, wrong for suffixes like
    .co.uk. The proper tool is the Public Suffix List (e.g. the `tldextract`
    package), worth adding if the dataset goes international.
    """
    return ".".join(host.split(".")[-2:])


def match_provider(host: str):
    """(label, type) if `host` belongs to a known provider, else None."""
    for suffix, label, kind in MX_PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return label, kind
    return None


def is_own_name(domain: str, host: str) -> bool:
    return host == domain or host.endswith("." + domain)


def classify_mx(domain: str, hosts: list[str], ptr_name: str = "") -> tuple[str, str]:
    """Return (mail_provider, provider_type) for the domain's primary MX.

    `ptr_name` is the reverse-DNS name of the MX host's IP. It only matters when
    the MX uses the company's own name (mail.firma.ch): then the PTR usually
    reveals the hoster actually running the server.
    """
    if not hosts:
        return "no MX", "none"
    if hosts == [""]:
        return "null MX", "none"

    primary = hosts[0]
    known = match_provider(primary)
    if known:
        return known
    if not is_own_name(domain, primary):
        return base_domain(primary), "unknown"

    # MX is under the company's own name: look through it via reverse DNS
    if ptr_name:
        known = match_provider(ptr_name)
        if known:
            return known
        if not is_own_name(domain, ptr_name):
            return base_domain(ptr_name), "unknown"
    return "self-hosted", "self-hosted"


# --- verdict -----------------------------------------------------------------------

def step_down(policy: str) -> str:
    """One level more lenient: reject -> quarantine -> none."""
    return {"reject": "quarantine", "quarantine": "none"}.get(policy, policy)


def effective_policy(policy: str, t: str, pct: int) -> str:
    """The policy the least strict receiver applies to failing mail.

    Receivers won't all move to RFC 9989 at once, and the two standards read
    the same record differently. Each ignores the other's tag (both say
    unknown tags must be ignored):
    - RFC 9989 receivers apply t=: with t=y, one level below p=.
    - RFC 7489 receivers apply pct=: mail outside the pct sample gets one
      level below p=. So p=reject; pct=0 still means "quarantine everything".
    """
    new_rules = step_down(policy) if t == "y" else policy
    old_rules = step_down(policy) if pct < 100 else policy
    return min(new_rules, old_rules, key=VALID_POLICIES.index)


def verdict(dmarc_policy: str, dmarc_t: str, dmarc_pct) -> str:
    """Same categories as the original dmarc-check.py, plus 'partial enforcement'.

    This mirrors how the least strict receiving server treats spoofed mail
    from the domain.
    """
    if not dmarc_policy:
        return "no DMARC"
    if dmarc_policy not in ("quarantine", "reject"):
        return "DMARC but no enforcement"  # p=none, malformed, multiple records

    if effective_policy(dmarc_policy, dmarc_t, dmarc_pct) != "none":
        return "protected"
    if dmarc_t != "y" and 0 < dmarc_pct < 100:
        # Old-rule receivers quarantine a share of the mail, new-rule receivers all of it
        return "partial enforcement"
    return "DMARC but no enforcement"  # p=quarantine with t=y or pct=0


# --- the network part ----------------------------------------------------------------

def check_mail(resolver, domain: str) -> dict:
    row = {col: "" for col in COLUMNS}
    row["domain"] = domain

    # Cache TXT answers for this domain's check: SPF includes are often shared
    # (e.g. two includes both pulling in spf.protection.outlook.com).
    cache = {}

    def get_txt(name):
        if name not in cache:
            cache[name] = txt(resolver, name)
        return cache[name]

    # 1. Required lookups. If any of these fail we can't say anything reliable,
    #    so the row is marked unknown rather than guessed.
    try:
        hosts = mx(resolver, domain)
        root_txt = get_txt(domain)
        dmarc_txt = get_txt(f"_dmarc.{domain}")
    except LookupFailed as e:
        row["error"] = str(e)
        row["verdict"] = "unknown"
        return row

    row["mx_hosts"] = " ".join(h for h in hosts if h)
    row["accepts_mail"] = bool(hosts) and hosts != [""]
    row.update(parse_spf(root_txt))
    row.update(parse_dmarc(dmarc_txt))
    if row["dmarc_policy"] in VALID_POLICIES:
        row["dmarc_effective_policy"] = effective_policy(
            row["dmarc_policy"], row["dmarc_t"], row["dmarc_pct"])
    row["verdict"] = verdict(row["dmarc_policy"], row["dmarc_t"], row["dmarc_pct"])

    # 2. Optional lookups. A failure here blanks only that field, and is noted.
    errors = []

    # Reverse DNS of the primary MX, used to see through mail.<own-domain>
    if hosts and hosts[0] and is_own_name(domain, hosts[0]):
        try:
            ips = a(resolver, hosts[0])
            row["mx_ptr"] = ptr(resolver, ips[0]) if ips else ""
        except LookupFailed as e:
            errors.append(f"mx ptr: {e}")
    row["mail_provider"], row["provider_type"] = classify_mx(domain, hosts, row["mx_ptr"])

    if row["spf_record"] and row["spf_all"] != "multiple records":
        try:
            n = count_spf_lookups(domain, get_txt)
            row["spf_lookups"] = n
            row["spf_too_many_lookups"] = n > SPF_LOOKUP_LIMIT
        except LookupFailed as e:
            errors.append(f"spf include: {e}")

    found = []
    for sel in COMMON_DKIM_SELECTORS:
        try:
            if any(is_dkim_key(r) for r in get_txt(f"{sel}._domainkey.{domain}")):
                found.append(sel)
        except LookupFailed:
            pass  # one flaky selector probe isn't worth reporting
    row["dkim_selectors"] = " ".join(found)

    for col, name, version in [
        ("mta_sts", f"_mta-sts.{domain}", "STSv1"),
        ("tls_rpt", f"_smtp._tls.{domain}", "TLSRPTv1"),
        ("bimi", f"default._bimi.{domain}", "BIMI1"),
    ]:
        try:
            row[col] = any(starts_with_version(r, version) for r in get_txt(name))
        except LookupFailed as e:
            errors.append(str(e))

    row["error"] = "; ".join(errors)
    return row
