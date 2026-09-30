"""
Mutation tests: take a known sample, change ONE thing, and check that the
matching finding appears or disappears. This proves each detection works
independently, not just that the final score looks right.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analyzer import PhishingAnalyzer

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def analyze(name, *swaps):
    with open(os.path.join(SAMPLES, name), "rb") as f:
        raw = f.read()
    for old, new in swaps:
        raw = raw.replace(old.encode(), new.encode())
    return PhishingAnalyzer(raw).analyze()


def titles(report):
    return [f["title"] for f in report["findings"]]


class MutationTests(unittest.TestCase):
    # ---- Authentication ----
    def test_spf_fail_finding_disappears_when_spf_passes(self):
        r = analyze("phish_paypal.eml", ("spf=fail", "spf=pass"))
        self.assertNotIn("SPF FAIL", titles(r))
        self.assertEqual(r["authentication"]["spf"], "pass")

    def test_dmarc_fail_alone_makes_legit_mail_suspicious(self):
        r = analyze("legit_github.eml", ("dmarc=pass", "dmarc=fail"))
        self.assertIn("DMARC FAIL", titles(r))
        self.assertEqual(r["risk_score"], 25)
        self.assertEqual(r["verdict"], "SUSPICIOUS - manual review")

    # ---- Attachments ----
    def test_renaming_attachment_removes_double_extension(self):
        r = analyze("phish_invoice.eml", ("Invoice_9931.pdf.exe", "Invoice_9931.pdf"))
        self.assertNotIn("Double extension (masquerading)", titles(r))
        self.assertEqual(r["risk_score"], 58)

    # ---- Header / lookalike ----
    def test_official_sender_domain_removes_impersonation(self):
        r = analyze("phish_invoice.eml", ("invoice-dhl-express.click", "dhl.com"))
        self.assertNotIn("Lookalike / typosquatted sender domain", titles(r))
        self.assertFalse(any("impersonates" in t for t in titles(r)))
        self.assertEqual(r["risk_score"], 48)

    def test_removing_all_bad_signals_gives_low_risk(self):
        r = analyze("phish_invoice.eml",
                    ("invoice-dhl-express.click", "dhl.com"),
                    ("Invoice_9931.pdf.exe", "Invoice_9931.pdf"))
        self.assertEqual(r["verdict"], "LOW RISK")

    # ---- Robustness ----
    def test_empty_input_does_not_crash(self):
        r = PhishingAnalyzer(b"").analyze()
        self.assertIn("verdict", r)

    def test_score_is_capped_at_100(self):
        r = analyze("phish_paypal.eml")
        self.assertGreater(sum(f["points"] for f in r["findings"]), 100)
        self.assertEqual(r["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
