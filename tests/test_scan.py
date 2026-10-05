"""Offline tests for the command-line helpers. Run with:  python -m pytest"""

import csv
import io

from sme_scan.scan import csv_safe


def test_csv_safe_neutralises_formula_triggers():
    for hostile in ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1", "=cmd|' /c calc'!a0"]:
        assert csv_safe(hostile) == "'" + hostile


def test_csv_safe_leaves_normal_values_alone():
    for value in ["mail.firma.ch", "v=DMARC1; p=reject", "Microsoft 365", "", True, 10]:
        assert csv_safe(value) == value


def test_csv_safe_output_survives_a_csv_round_trip():
    buf = io.StringIO()
    csv.writer(buf).writerow([csv_safe("=HYPERLINK(\"http://x\")"), csv_safe("mx.hoster.ch")])
    row = next(csv.reader(io.StringIO(buf.getvalue())))
    assert row == ["'=HYPERLINK(\"http://x\")", "mx.hoster.ch"]
