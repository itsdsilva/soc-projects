"""
Coverage for every detection that the sample-based tests never reach.

The samples cover double-extension attachments, DMARC/SPF results and the
paypa1 lookalike. Everything below is reachable from attacker-controlled input
but was previously untested: DKIM failure and misalignment, the Received-SPF
fallback, punycode / user@host / plain-HTTP / deep-subdomain URLs, and the
executable, macro, HTML, archive and RTL-override attachment rules.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from mailbuild import ALL_PASS, analyze, titles


class AuthenticationTests(unittest.TestCase):
    def test_dkim_fail(self):
        r = analyze(auth_results="spf=pass smtp.mailfrom=t@example.com; dkim=fail; dmarc=fail")
        self.assertIn("DKIM FAIL", titles(r))

    def test_dkim_pass_but_not_aligned_with_from(self):
        r = analyze(from_="Test <t@example.com>",
                    auth_results="spf=pass smtp.mailfrom=t@example.com; "
                                 "dkim=pass header.d=attacker.example; dmarc=pass")
        self.assertIn("DKIM passes but is NOT aligned with From", titles(r))

    def test_spf_pass_but_not_aligned_with_from(self):
        r = analyze(from_="Test <t@example.com>",
                    auth_results="spf=pass smtp.mailfrom=bounce@bulkmailer.example; "
                                 "dkim=pass header.d=example.com; dmarc=pass")
        self.assertIn("SPF passes but is NOT aligned with From", titles(r))

    def test_aligned_triple_pass_raises_no_alignment_finding(self):
        r = analyze(auth_results=ALL_PASS)
        self.assertNotIn("DKIM passes but is NOT aligned with From", titles(r))
        self.assertNotIn("SPF passes but is NOT aligned with From", titles(r))

    def test_received_spf_header_used_when_no_authentication_results(self):
        r = analyze(received_spf="pass (google.com: domain of x designates 1.2.3.4 as permitted sender)")
        self.assertEqual(r["authentication"]["spf"], "pass")

    def test_received_spf_softfail(self):
        r = analyze(received_spf="softfail (google.com: domain of x is inconclusive)")
        self.assertEqual(r["authentication"]["spf"], "softfail")
        self.assertIn("SPF SOFTFAIL", titles(r))

    def test_spf_softfail_from_authentication_results(self):
        r = analyze(auth_results="spf=softfail; dkim=none; dmarc=fail")
        self.assertIn("SPF SOFTFAIL", titles(r))

    def test_spf_none(self):
        r = analyze(auth_results="spf=none; dkim=pass header.d=example.com; dmarc=none")
        self.assertIn("SPF NONE", titles(r))

    def test_missing_dkim_and_dmarc_reported(self):
        r = analyze(auth_results="spf=pass smtp.mailfrom=t@example.com")
        self.assertIn("No DKIM signature", titles(r))
        self.assertIn("No DMARC result", titles(r))

    def test_no_authentication_headers_at_all_is_unknown_not_clean(self):
        r = analyze()
        self.assertIn("No Authentication-Results header", titles(r))
        self.assertEqual(r["authentication"], {"spf": None, "dkim": None, "dmarc": None})


class UrlTests(unittest.TestCase):
    def test_raw_ip_url(self):
        self.assertIn("URL uses a raw IP address", titles(analyze(body="http://45.133.1.77/login")))

    def test_url_shortener(self):
        self.assertIn("URL shortener hides destination", titles(analyze(body="http://bit.ly/3abc")))

    def test_punycode_host(self):
        self.assertIn("Punycode (IDN homograph) domain",
                      titles(analyze(body="http://xn--80ak6aa92e.com/login")))

    def test_credentials_at_trick(self):
        self.assertIn("Credentials/@ trick in URL",
                      titles(analyze(body="http://paypal.com@evil.example/login")))

    def test_plain_http_link(self):
        self.assertIn("Unencrypted HTTP link", titles(analyze(body="http://plain.example/page")))

    def test_https_link_not_flagged_as_plain_http(self):
        self.assertNotIn("Unencrypted HTTP link", titles(analyze(body="https://ok.example/page")))

    def test_excessive_subdomains(self):
        self.assertIn("Excessive subdomains",
                      titles(analyze(body="https://a.b.c.d.e.example.net/")))

    def test_suspicious_tld(self):
        self.assertIn("Suspicious TLD .zip", titles(analyze(body="https://archive.zip/file")))

    def test_anchor_text_mismatch(self):
        html = '<a href="https://evil.example/login">https://paypal.com</a>'
        self.assertIn("Link text does not match link target", titles(analyze(html=html)))

    def test_matching_anchor_text_not_flagged(self):
        html = '<a href="https://github.com/x">https://github.com/x</a>'
        self.assertNotIn("Link text does not match link target", titles(analyze(html=html)))

    def test_html_and_plain_links_are_both_collected(self):
        html = '<a href="https://a.example/1">a</a>'
        r = analyze(body="https://b.example/2", html=html)
        self.assertIn("https://a.example/1", r["iocs"]["urls"])
        self.assertIn("https://b.example/2", r["iocs"]["urls"])

    def test_non_http_href_is_ignored(self):
        r = analyze(html='<a href="mailto:x@example.com">mail</a>'
                         '<a href="#anchor">jump</a>')
        self.assertEqual(r["iocs"]["urls"], [])


class AttachmentTests(unittest.TestCase):
    def test_plain_executable_attachment(self):
        r = analyze(attachments=[("payload.exe", b"MZ fake", "application/octet-stream")])
        self.assertIn("Executable/script attachment (.exe)", titles(r))

    def test_script_attachment(self):
        r = analyze(attachments=[("run.ps1", b"IEX", "application/octet-stream")])
        self.assertIn("Executable/script attachment (.ps1)", titles(r))

    def test_macro_enabled_office(self):
        r = analyze(attachments=[("payroll.xlsm", b"fake", "application/vnd.ms-excel.sheet.macroEnabled")])
        self.assertIn("Macro-enabled Office file (.xlsm)", titles(r))

    def test_html_attachment_smuggling(self):
        r = analyze(attachments=[("invoice.html", b"<form>", "text/html")])
        self.assertIn("HTML attachment (possible HTML smuggling / fake login page)", titles(r))

    def test_svg_attachment(self):
        r = analyze(attachments=[("logo.svg", b"<svg/>", "image/svg+xml")])
        self.assertIn("HTML attachment (possible HTML smuggling / fake login page)", titles(r))

    def test_archive_attachment(self):
        r = analyze(attachments=[("bundle.zip", b"PK", "application/zip")])
        self.assertIn("Archive attachment (.zip)", titles(r))

    def test_rtl_override_filename(self):
        r = analyze(attachments=[("invoice\u202egnp.exe", b"MZ", "application/octet-stream")])
        self.assertIn("Right-to-left override in filename", titles(r))

    def test_hashes_are_recorded_for_every_attachment(self):
        r = analyze(attachments=[("a.exe", b"MZ", "application/octet-stream"),
                                ("b.txt", b"hello", "text/plain")])
        names = sorted(h["file"] for h in r["iocs"]["hashes"])
        self.assertEqual(names, ["a.exe", "b.txt"])
        for h in r["iocs"]["hashes"]:
            self.assertEqual(len(h["sha256"]), 64)
            self.assertEqual(len(h["md5"]), 32)
            self.assertEqual(h["size"], len(b"MZ") if h["file"] == "a.exe" else len(b"hello"))

    def test_ordinary_pdf_is_not_flagged(self):
        r = analyze(attachments=[("statement.pdf", b"%PDF-1.4", "application/pdf")])
        self.assertEqual([t for t in titles(r) if t.startswith(("Executable", "Archive", "HTML", "Double", "Macro"))], [])


class HeaderTests(unittest.TestCase):
    def test_display_name_holding_a_different_address(self):
        r = analyze(from_='"victim@bank.example" <t@evil.example>')
        self.assertIn("Display name contains a different email address", titles(r))

    def test_display_name_impersonating_brand(self):
        r = analyze(from_='"PayPal Support" <t@evil.example>')
        self.assertIn("Display name impersonates 'paypal'", titles(r))

    def test_display_name_brand_on_official_domain_not_flagged(self):
        r = analyze(from_='"PayPal Support" <t@paypal.com>', auth_results=ALL_PASS)
        self.assertNotIn("Display name impersonates 'paypal'", titles(r))

    def test_missing_message_id(self):
        self.assertIn("Missing Message-ID", titles(analyze(message_id=None)))

    def test_message_id_domain_differs_from_from(self):
        r = analyze(from_="Test <t@example.com>", message_id="<abc@other.example>")
        self.assertIn("Message-ID domain differs from From", titles(r))

    def test_missing_date(self):
        self.assertIn("Missing Date header", titles(analyze(date=None)))

    def test_no_received_headers(self):
        self.assertIn("No Received headers", titles(analyze()))

    def test_return_path_domain_differs_from_from(self):
        r = analyze(from_="Test <t@example.com>", return_path="bounce@bulkmailer.example")
        self.assertIn("Return-Path domain differs from From", titles(r))

    def test_reply_to_domain_differs_from_from(self):
        r = analyze(from_="Test <t@example.com>", reply_to="other@elsewhere.example")
        self.assertIn("Reply-To domain differs from From", titles(r))

    def test_reply_to_same_domain_not_flagged(self):
        r = analyze(from_="Test <t@example.com>", reply_to="other@example.com")
        self.assertNotIn("Reply-To domain differs from From", titles(r))

    def test_origin_ip_taken_from_received_chain(self):
        r = analyze(received=["from mx.example.com (mx.example.com [192.0.2.10]) by relay.example.net",
                              "from sender.evil.example (sender.evil.example [45.133.1.77]) by mx.example.com"])
        self.assertEqual(r["meta"]["origin_ip"], "45.133.1.77")
        self.assertIn("45.133.1.77", r["iocs"]["ips"])

    def test_x_originating_ip_recorded(self):
        r = analyze(x_originating_ip="45.133.1.77")
        self.assertIn("45.133.1.77", r["iocs"]["ips"])

    def test_private_hop_not_reported_as_origin(self):
        r = analyze(received=["from internal (internal [10.0.0.5]) by mail.example.com",
                              "from sender.evil.example (sender.evil.example [45.133.1.77]) by internal"])
        self.assertEqual(r["meta"]["origin_ip"], "45.133.1.77")


class ContentTests(unittest.TestCase):
    def test_urgency_language(self):
        r = analyze(body="URGENT: act now, your account will be suspended immediately")
        self.assertIn("Urgency / pressure language", titles(r))

    def test_single_urgency_word_is_not_enough(self):
        r = analyze(body="Please review the attached report, thanks.")
        self.assertNotIn("Urgency / pressure language", titles(r))

    def test_credential_bait(self):
        r = analyze(body="Please verify your account and update your password")
        self.assertIn("Credential-harvesting language", titles(r))

    def test_password_next_to_attachment_mention(self):
        r = analyze(body="The zip archive password is 1234")
        self.assertIn("Password mentioned alongside attachment", titles(r))


class ScoreTests(unittest.TestCase):
    def test_verdict_thresholds(self):
        cases = [(0, "LOW RISK"), (19, "LOW RISK"), (20, "SUSPICIOUS - manual review"),
                 (49, "SUSPICIOUS - manual review"), (50, "LIKELY PHISHING"),
                 (74, "LIKELY PHISHING"), (75, "PHISHING (high confidence)"),
                 (100, "PHISHING (high confidence)")]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(_verdict_for(score), expected)

    def test_findings_sorted_by_severity_then_points(self):
        r = analyze(auth_results="spf=fail; dkim=fail; dmarc=fail",
                    body="http://45.133.1.77/x https://archive.zip/y",
                    attachments=[("a.exe", b"MZ", "application/octet-stream")])
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        keys = [(order[f["severity"]], -f["points"]) for f in r["findings"]]
        self.assertEqual(keys, sorted(keys))

    def test_identical_findings_are_suppressed(self):
        r = analyze(body="http://45.133.1.77/a http://45.133.1.77/a")
        self.assertEqual(len([t for t in titles(r) if t == "URL uses a raw IP address"]), 1)

    def test_distinct_urls_each_keep_their_own_finding(self):
        """Dedup keys on title+detail, so a different path is a different IOC."""
        r = analyze(body="http://45.133.1.77/a http://45.133.1.77/b")
        self.assertEqual(len([t for t in titles(r) if t == "URL uses a raw IP address"]), 2)
        self.assertEqual(len(r["iocs"]["urls"]), 2)

    def test_mitre_techniques_deduplicated_and_sorted(self):
        r = analyze(auth_results="spf=fail; dkim=fail; dmarc=fail")
        self.assertEqual(r["mitre_techniques"], sorted(set(r["mitre_techniques"])))


def _verdict_for(score):
    from analyzer import PhishingAnalyzer
    a = PhishingAnalyzer(b"")
    a.findings = []
    r = a.build_report()
    # rebuild with a synthetic finding worth `score` points
    from analyzer import Finding
    a.findings = [Finding("LOW", "Test", "synthetic", "d", score)]
    return a.build_report()["verdict"]


if __name__ == "__main__":
    unittest.main()
