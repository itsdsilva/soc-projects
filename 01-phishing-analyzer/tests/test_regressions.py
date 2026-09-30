"""
Regression tests for two bugs found by probing outside the sample set.

1. defang() rewrote every "http" in the string, not just the scheme, so a host
   like httpbin.org was published as hxxpbin[.]org - a different domain from
   the one observed, so a blocklist entry built from it would never match.
2. check_urls() called urlparse() unguarded, so a malformed URL in the body
   (attacker-controlled) raised ValueError and killed the whole analysis.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from analyzer import PhishingAnalyzer, defang


def build(body, extra_headers=""):
    return (f"From: Test <t@example.com>\r\n"
            f"To: v@example.com\r\n"
            f"Subject: t\r\n"
            f"Date: Tue, 29 Sep 2026 10:00:00 +0000\r\n"
            f"Message-ID: <a@example.com>\r\n"
            f"{extra_headers}"
            f"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n{body}").encode()


class DefangRegression(unittest.TestCase):
    def test_host_containing_http_is_not_corrupted(self):
        self.assertEqual(defang("https://httpbin.org/redirect"),
                         "hxxps://httpbin[.]org/redirect")
        self.assertEqual(defang("http://http-only.example.net/a"),
                         "hxxp://http-only[.]example[.]net/a")

    def test_scheme_is_still_defanged(self):
        self.assertEqual(defang("http://evil.example/a"),
                         "hxxp://evil[.]example/a")
        self.assertEqual(defang("https://evil.example/a"),
                         "hxxps://evil[.]example/a")

    def test_nested_url_is_still_defanged(self):
        out = defang("https://ok.example/?u=http://evil.example/a")
        self.assertNotIn("http://", out)
        self.assertIn("hxxp://evil[.]example", out)

    def test_bare_domain_and_ip(self):
        self.assertEqual(defang("evil.example"), "evil[.]example")
        self.assertEqual(defang("45.133.1.77"), "45[.]133[.]1[.]77")

    def test_defanged_ioc_in_report_still_reconstructs_the_real_host(self):
        raw = build('visit https://httpbin.org/x',
                    "Reply-To: bounce@http-relay.com\r\n")
        report = PhishingAnalyzer(raw).analyze()
        url = report["iocs"]["urls"][0]
        self.assertEqual(url, "https://httpbin.org/x")
        self.assertIn("httpbin[.]org", defang(url))
        self.assertNotIn("hxxpbin", defang(url))


class MalformedUrlRegression(unittest.TestCase):
    def test_malformed_ipv6_url_does_not_abort_analysis(self):
        for bad in ("http://[::1", "http://[", "http://[fe80::1"):
            with self.subTest(url=bad):
                report = PhishingAnalyzer(build(f"click {bad} now")).analyze()
                self.assertIn("verdict", report)

    def test_malformed_url_still_keeps_other_findings(self):
        """The bad URL must be survivable, not silently swallow the report."""
        raw = build("click http://[ now\nURGENT: verify your account immediately\n"
                    "https://paypa1-secure.com/login")
        report = PhishingAnalyzer(raw).analyze()
        titles = [f["title"] for f in report["findings"]]
        self.assertIn("Unparseable URL", titles)
        self.assertIn("Link domain imitates a known brand", titles)
        self.assertGreater(report["risk_score"], 0)

    def test_malformed_url_in_html_href_does_not_abort_analysis(self):
        raw = (b"From: Test <t@example.com>\r\nSubject: t\r\n"
               b"Date: Tue, 29 Sep 2026 10:00:00 +0000\r\n"
               b"Message-ID: <a@example.com>\r\n"
               b"Content-Type: text/html; charset=\"utf-8\"\r\n\r\n"
               b'<a href="http://[::1">click</a>')
        report = PhishingAnalyzer(raw).analyze()
        self.assertIn("verdict", report)

    def test_malformed_url_in_redirect_parameter_is_tolerated(self):
        report = PhishingAnalyzer(build("https://ok.example/?u=http://[::1")).analyze()
        self.assertIn("verdict", report)


if __name__ == "__main__":
    unittest.main()
