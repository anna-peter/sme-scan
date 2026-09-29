#!/usr/bin/env python3
"""
dmarc_check.py — measure email-authentication hygiene across a list of domains.

This is a PASSIVE check. SPF, DMARC and DKIM policy records are published in
public DNS precisely so that anyone can read them. Querying them is the same
thing every mail server on the internet does before accepting a message. No
systems are probed, nothing is sent, nothing is accessed that isn't published.

Usage:
    pip install dnspython --break-system-packages
    python3 dmarc_check.py domains.csv --column Website --out results.csv

Input:  a CSV with a column containing domains or URLs (either is fine)
Output: results.csv with one row per domain, plus a summary printed to screen
"""

import argparse
import csv
import re
import sys
import time
from collections import Counter
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit("Missing dependency. Run: pip install dnspython --break-system-packages")


# --- domain cleanup ----------------------------------------------------------

def clean_domain(raw):
    """Turn 'https://www.example.ch/kontakt' into 'example.ch'."""
    if not raw:
        return None
    s = str(raw).strip().lower()
    if not s or s in ("not found", "n/a", "-"):
        return None
    if "://" not in s:
        s = "https://" + s
    host = urlparse(s).netloc or urlparse(s).path
    host = host.split("/")[0].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host if "." in host else None


# --- DNS lookups -------------------------------------------------------------

def make_resolver(timeout):
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    # Public resolvers, so results don't depend on your ISP's cache
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    return r


def txt_records(resolver, name):
    """Return TXT records as strings, or None if the lookup failed entirely."""
    try:
        answers = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    out = []
    for rdata in answers:
        # TXT records arrive as one or more byte chunks that must be joined
        joined = "".join(
            part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
            for part in rdata.strings
        )
        out.append(joined)
    return out


def has_mx(resolver, domain):
    try:
        resolver.resolve(domain, "MX")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except dns.exception.DNSException:
        return None


def parse_dmarc_policy(records):
    """Extract the p= policy from a DMARC record: none | quarantine | reject."""
    for rec in records or []:
        if rec.lower().startswith("v=dmarc1"):
            m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", rec, re.I)
            return m.group(1).lower() if m else "malformed"
    return None


def parse_spf(records):
    """Return the SPF record and its 'all' qualifier, if present."""
    for rec in records or []:
        if rec.lower().startswith("v=spf1"):
            m = re.search(r"([~\-+?])all\b", rec, re.I)
            qualifier = {
                "-": "hard fail",
                "~": "soft fail",
                "+": "pass all (ineffective)",
                "?": "neutral (ineffective)",
            }.get(m.group(1) if m else None, "no all mechanism")
            return rec, qualifier
    return None, None


def check_domain(resolver, domain):
    row = {
        "domain": domain,
        "has_mx": "",
        "spf": "",
        "spf_policy": "",
        "dmarc": "",
        "dmarc_policy": "",
        "verdict": "",
        "error": "",
    }

    mx = has_mx(resolver, domain)
    if mx is None:
        row["error"] = "DNS lookup failed"
        row["verdict"] = "unknown"
        return row
    row["has_mx"] = "yes" if mx else "no"

    spf_records = txt_records(resolver, domain)
    dmarc_records = txt_records(resolver, f"_dmarc.{domain}")

    if spf_records is None or dmarc_records is None:
        row["error"] = "DNS lookup failed"
        row["verdict"] = "unknown"
        return row

    spf_rec, spf_policy = parse_spf(spf_records)
    dmarc_policy = parse_dmarc_policy(dmarc_records)

    row["spf"] = "yes" if spf_rec else "no"
    row["spf_policy"] = spf_policy or ""
    row["dmarc"] = "yes" if dmarc_policy else "no"
    row["dmarc_policy"] = dmarc_policy or ""

    # Verdict mirrors how a receiving mail server would treat the domain.
    # DMARC p=none publishes a policy but instructs no action, so spoofed mail
    # still gets delivered — that's why it counts as "partial", not "protected".
    if not dmarc_policy:
        row["verdict"] = "no DMARC"
    elif dmarc_policy in ("none", "malformed"):
        row["verdict"] = "DMARC but no enforcement"
    else:
        row["verdict"] = "protected"

    return row


# --- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_csv")
    ap.add_argument("--column", default="Website",
                    help="column holding the domain or website URL")
    ap.add_argument("--out", default="dmarc_results.csv")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--delay", type=float, default=0.1,
                    help="pause between domains, to stay polite to resolvers")
    args = ap.parse_args()

    # read + dedupe
    domains, skipped = [], 0
    with open(args.input_csv, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if args.column not in (reader.fieldnames or []):
            sys.exit(f"Column '{args.column}' not found. Available: {reader.fieldnames}")
        seen = set()
        for r in reader:
            d = clean_domain(r.get(args.column))
            if not d:
                skipped += 1
            elif d not in seen:
                seen.add(d)
                domains.append(d)

    if not domains:
        sys.exit("No usable domains found.")

    print(f"{len(domains)} unique domains ({skipped} rows skipped)\n")

    resolver = make_resolver(args.timeout)
    rows = []
    for i, d in enumerate(domains, 1):
        row = check_domain(resolver, d)
        rows.append(row)
        print(f"  [{i}/{len(domains)}] {d:<40} {row['verdict']}")
        time.sleep(args.delay)

    cols = ["domain", "has_mx", "spf", "spf_policy", "dmarc", "dmarc_policy",
            "verdict", "error"]
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    # --- summary -------------------------------------------------------------
    usable = [r for r in rows if r["verdict"] != "unknown"]
    n = len(usable)
    if not n:
        sys.exit("\nAll lookups failed — check your network.")

    verdicts = Counter(r["verdict"] for r in usable)
    no_spf = sum(1 for r in usable if r["spf"] == "no")
    no_dmarc = sum(1 for r in usable if r["dmarc"] == "no")
    weak = sum(1 for r in usable if r["dmarc_policy"] in ("none", "malformed"))
    enforcing = sum(1 for r in usable if r["dmarc_policy"] in ("quarantine", "reject"))

    def pct(x):
        return f"{100 * x / n:.1f}%"

    print(f"\n{'='*60}")
    print(f"{n} domains resolved ({len(rows) - n} failed)\n")
    print(f"  no SPF record            {no_spf:>4}   {pct(no_spf)}")
    print(f"  no DMARC record          {no_dmarc:>4}   {pct(no_dmarc)}")
    print(f"  DMARC without enforcement{weak:>4}   {pct(weak)}")
    print(f"  DMARC enforcing          {enforcing:>4}   {pct(enforcing)}")
    print(f"\n  no meaningful protection {no_dmarc + weak:>4}   {pct(no_dmarc + weak)}")
    print(f"{'='*60}")
    print("\nThe headline number is the last one: domains that either publish no")
    print("DMARC policy at all, or publish one that instructs receivers to take")
    print("no action. Both leave the domain spoofable in practice.")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()