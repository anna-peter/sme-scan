#!/usr/bin/env python3
"""
Passive security-posture scan of a list of domains.

Only public DNS records are read: the same records every mail server looks
up before accepting a message. Nothing is probed, sent, or logged into.

Usage (from the repo root):
    python -m sme_scan.scan zh_sme_domains_extensive.csv --out results/mail_extensive.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

from sme_scan.checks.mail import COLUMNS, check_mail
from sme_scan.dns_utils import make_resolver


def clean_domain(raw) -> str | None:
    """Turn 'https://www.example.ch/kontakt' into 'example.ch'."""
    if not raw:
        return None
    s = str(raw).strip().lower()
    if not s or s in ("not found", "n/a", "-"):
        return None
    if "://" not in s:
        s = "https://" + s
    host = urlparse(s).netloc.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host if "." in host else None


def read_domains(path: str, column: str) -> list[str]:
    domains, seen, skipped = [], set(), 0
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if column not in (reader.fieldnames or []):
            sys.exit(f"Column '{column}' not found. Available: {reader.fieldnames}")
        for r in reader:
            d = clean_domain(r.get(column))
            if d is None:
                skipped += 1
            elif d not in seen:
                seen.add(d)
                domains.append(d)
    print(f"{len(domains)} unique domains ({skipped} rows skipped)\n")
    return domains


def scan_one(domain: str, timeout: float) -> dict:
    # One resolver per task: simplest way to be sure threads never share state
    return check_mail(make_resolver(timeout), domain)


def print_summary(rows: list[dict]) -> None:
    usable = [r for r in rows if r["verdict"] != "unknown"]
    n = len(usable)
    if not n:
        sys.exit("\nAll lookups failed - check your network.")

    def line(label, count):
        print(f"  {label:<34}{count:>5}   {100 * count / n:5.1f}%")

    print(f"\n{'=' * 60}\n{n} domains resolved ({len(rows) - n} failed)\n")
    print("DMARC verdict")
    for v, c in Counter(r["verdict"] for r in usable).most_common():
        line(v, c)
    print("\nDetails")
    line("DMARC with reporting (rua)", sum(r["dmarc_rua"] is True for r in usable))
    line("no SPF record", sum(not r["spf_record"] for r in usable))
    line("SPF over 10-lookup limit", sum(r["spf_too_many_lookups"] is True for r in usable))
    line("DKIM key found (common selectors)", sum(bool(r["dkim_selectors"]) for r in usable))
    line("MTA-STS", sum(r["mta_sts"] is True for r in usable))
    print("\nProvider type")
    for t, c in Counter(r["provider_type"] for r in usable).most_common():
        line(t, c)
    print("\nMail provider (top 12)")
    for p, c in Counter(r["mail_provider"] for r in usable).most_common(12):
        line(p, c)
    print("=" * 60)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("input_csv")
    ap.add_argument("--column", default="Website",
                    help="column holding the domain or website URL")
    ap.add_argument("--out", default="results/mail_results.csv")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--workers", type=int, default=8,
                    help="domains checked in parallel (keep it modest to stay polite)")
    args = ap.parse_args()

    domains = read_domains(args.input_csv, args.column)
    if not domains:
        sys.exit("No usable domains found.")

    # DNS queries spend almost all their time waiting on the network, so threads
    # help a lot here even with Python's GIL: while one thread waits, others run.
    rows = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_one, d, args.timeout): d for d in domains}
        for i, fut in enumerate(as_completed(futures), 1):
            row = fut.result()
            rows.append(row)
            print(f"  [{i}/{len(domains)}] {row['domain']:<40} {row['verdict']}")

    # as_completed yields in finishing order; restore input order for the file
    order = {d: i for i, d in enumerate(domains)}
    rows.sort(key=lambda r: order[r["domain"]])

    # Record when the scan ran, so repeated scans can be compared over time
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS + ["scanned_at"])
        w.writeheader()
        for r in rows:
            w.writerow({**r, "scanned_at": scanned_at})

    print_summary(rows)
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
