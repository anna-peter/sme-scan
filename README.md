# sme-scan

Measure the email-authentication posture of a list of domains: SPF, DMARC,
DKIM, MTA-STS, TLS-RPT, BIMI, and who operates each domain's mail.

Built to study small and medium-sized businesses in the canton of Zurich.

## Passive by design

The scanner only reads **public DNS records**, the same lookups every mail
server performs before accepting a message. It sends no email, probes no
ports, and logs into nothing.

The company lists and scan results are **not part of this repository**. They
name real businesses next to their weaknesses. Findings are published in
aggregate only.

## Setup

Requires Python 3.8+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

The input is a CSV with a column containing domains or website URLs
(`https://www.example.ch/kontakt` is cleaned to `example.ch`):

```csv
Company,Website,Category
Example AG,https://www.example.ch,Treuhand
```

Run from the repository root:

```bash
python -m sme_scan.scan companies.csv --column Website --out results/mail.csv
```

Options: `--workers` (parallel domains, default 8), `--timeout` (seconds per
DNS query, default 5).

The output has one row per domain, and a summary is printed to the terminal.
`analysis.ipynb` joins the results back to the input list for analysis by
category.

## What is measured

| Column | Meaning |
|---|---|
| `verdict` | `protected` (DMARC quarantine/reject at 100%), `partial enforcement`, `DMARC but no enforcement`, `no DMARC`, or `unknown` (DNS lookup failed) |
| `dmarc_policy`, `dmarc_sp`, `dmarc_pct` | DMARC policy, effective subdomain policy, percentage applied |
| `dmarc_rua`, `dmarc_ruf` | Whether aggregate / forensic reports are requested |
| `spf_all` | How the SPF record ends: hard fail, soft fail, redirect, ... |
| `spf_lookups`, `spf_too_many_lookups` | DNS lookups SPF evaluation needs, and whether it exceeds the RFC 7208 limit of 10 |
| `dkim_selectors` | DKIM keys found among common selector names. **A lower bound**: selectors can't be listed, so "none found" means unknown |
| `mta_sts`, `tls_rpt`, `bimi` | Whether these records are published |
| `mail_provider`, `provider_type` | Who runs the mail, from the MX records. When the MX uses the company's own name (`mail.firma.ch`), reverse DNS of its IP identifies the actual host |

## Tests

The parsers are pure functions and are tested offline:

```bash
python -m pytest
```

## Layout

```
sme_scan/
  dns_utils.py      all DNS access
  checks/mail.py    email checks: parsing, provider classification, verdict
  scan.py           command line: read CSV, scan in parallel, write results
tests/              offline tests for the parsers
analysis.ipynb      analysis of scan results
```

## License

Copyright (c) 2026 Anna Peter. Licensed under the
[GNU Affero General Public License v3.0](LICENSE): you may use, modify and
share this code, but if you run a modified version as a network service, you
must make your source code available to its users.

For other licensing arrangements, contact the author.
