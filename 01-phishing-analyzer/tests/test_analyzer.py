import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analyzer import PhishingAnalyzer, check_lookalike, base_domain

S = os.path.join(os.path.dirname(__file__), "..", "samples")

def run(name):
    with open(os.path.join(S, name), "rb") as f:
        return PhishingAnalyzer(f.read()).analyze()

def titles(r):
    return [f["title"] for f in r["findings"]]

class Tests(unittest.TestCase):
    def test_phish_paypal(self):
        r = run("phish_paypal.eml")
        self.assertGreaterEqual(r["risk_score"], 75)
        self.assertEqual(r["authentication"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        t = titles(r)
        self.assertIn("DMARC FAIL", t)
        self.assertIn("Reply-To domain differs from From", t)
        self.assertIn("Link text does not match link target", t)
        self.assertIn("URL uses a raw IP address", t)
        self.assertEqual(r["meta"]["origin_ip"], "45.133.1.77")

    def test_phish_invoice_passes_auth_but_still_flagged(self):
        r = run("phish_invoice.eml")
        self.assertEqual(r["authentication"]["dmarc"], "pass")   # attacker owns the domain
        self.assertIn("Double extension (masquerading)", titles(r))
        self.assertGreaterEqual(r["risk_score"], 50)
        self.assertEqual(len(r["iocs"]["hashes"]), 1)

    def test_legit(self):
        r = run("legit_github.eml")
        self.assertLess(r["risk_score"], 20)
        self.assertEqual(r["verdict"], "LOW RISK")

    def test_trusted_aux_not_flagged_as_lookalike(self):
        """linkedinmobileapp.com, licdn.com etc. are owned by their brand
        and must not be treated as typosquats."""
        self.assertIsNone(check_lookalike("linkedinmobileapp.com"))
        self.assertIsNone(check_lookalike("licdn.com"))
        self.assertIsNone(check_lookalike("googleadservices.com"))
        # still catches actual typosquats
        self.assertIsNotNone(check_lookalike("linkedin-secure.com"))

    def test_lookalike(self):
        self.assertIsNotNone(check_lookalike("paypa1-secure.com"))
        self.assertIsNotNone(check_lookalike("rnicrosoft.com"))
        self.assertIsNone(check_lookalike("paypal.com"))
        self.assertIsNone(check_lookalike("mail.google.com"))

    def test_base_domain(self):
        self.assertEqual(base_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(base_domain("mail.github.com"), "github.com")

if __name__ == "__main__":
    unittest.main()
