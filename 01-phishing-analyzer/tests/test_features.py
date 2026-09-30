"""
Tests for the features that were advertised in the README but never exercised:
redirect unwrapping, the auth-aware brand-lookalike downgrade, DNS record
lookups, and the command-line entry point.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from mailbuild import ALL_PASS, analyze, eml, titles
import analyzer
from analyzer import (PhishingAnalyzer, base_domain, check_lookalike,
                      from_matches_brand, normalize_lookalike, print_report,
                      unwrap_redirect)


class BaseDomainTests(unittest.TestCase):
    def test_two_level_tld(self):
        self.assertEqual(base_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(base_domain("x.example.com.au"), "example.com.au")

    def test_plain_domain(self):
        self.assertEqual(base_domain("mail.github.com"), "github.com")
        self.assertEqual(base_domain("github.com"), "github.com")

    def test_ip_is_returned_unchanged(self):
        self.assertEqual(base_domain("45.133.1.77"), "45.133.1.77")
        self.assertEqual(base_domain("::1"), "::1")

    def test_case_and_trailing_dot_normalised(self):
        self.assertEqual(base_domain("MAIL.GitHub.COM."), "github.com")

    def test_empty(self):
        self.assertEqual(base_domain(""), "")
        self.assertEqual(base_domain(None), "")


class NormalizeLookalikeTests(unittest.TestCase):
    def test_digit_substitutions(self):
        self.assertEqual(normalize_lookalike("paypa1"), "paypal")
        self.assertEqual(normalize_lookalike("micros0ft"), "microsoft")

    def test_rn_substitution(self):
        self.assertEqual(normalize_lookalike("rnicrosoft"), "microsoft")


class LookalikeTests(unittest.TestCase):
    def test_official_domain_not_flagged(self):
        self.assertIsNone(check_lookalike("paypal.com"))
        self.assertIsNone(check_lookalike("mail.google.com"))
        self.assertIsNone(check_lookalike("github.com"))

    def test_typosquat_flagged(self):
        for d in ("paypa1-secure.com", "rnicrosoft.com", "linkedin-secure.com"):
            with self.subTest(domain=d):
                self.assertIsNotNone(check_lookalike(d))

    def test_similarity_typosquat_flagged_with_transposition(self):
        """Single-character typos, caught by ratio rather than substring."""
        for d, brand in (("netfilx.com", "netflix"), ("linkedon.com", "linkedin"),
                         ("dropbpx.com", "dropbox"), ("microsft.com", "microsoft"),
                         ("docuslgn.com", "docusign")):
            with self.subTest(domain=d):
                hit = check_lookalike(d)
                self.assertIsNotNone(hit)
                self.assertEqual(hit[0], brand)
                self.assertIn("near-match", hit[1])
                self.assertIn("typosquat", hit[1])

    def test_similarity_path_ignores_distant_names(self):
        for d in ("completely-different-name.com", "icicibank.com", "zyxwvut.com"):
            with self.subTest(domain=d):
                self.assertIsNone(check_lookalike(d))

    def test_empty_or_dotless_input(self):
        self.assertIsNone(check_lookalike(""))
        self.assertIsNone(check_lookalike(None))

    def test_brand_in_registrable_label_flagged(self):
        self.assertIsNotNone(check_lookalike("paypal-secure.example"))

    def test_brand_under_a_third_party_domain_is_not_flagged(self):
        """Only the registrable base domain's first label is judged, so a
        partner domain like paypal-integration.acme.com is not a false
        positive - the brand string sits under someone else's domain."""
        for d in ("paypal-integration.example.com", "paypal.evil.example"):
            with self.subTest(domain=d):
                self.assertIsNone(check_lookalike(d))

    def test_unrelated_domain_not_flagged(self):
        for d in ("example.com", "acme-corp.example", "acme.example"):
            with self.subTest(domain=d):
                self.assertIsNone(check_lookalike(d))

    def test_github_owned_aux_domains_not_flagged(self):
        for d in ("github.io", "githubusercontent.com", "githubassets.com"):
            with self.subTest(domain=d):
                self.assertIsNone(check_lookalike(d))


class UnwrapRedirectTests(unittest.TestCase):
    def test_known_wrapper_keys(self):
        for key in ("url", "u", "target", "redirect", "redirect_uri", "r", "dest", "to", "link"):
            with self.subTest(key=key):
                self.assertEqual(
                    unwrap_redirect(f"https://trk.example/?{key}=https://evil.example/a"),
                    "https://evil.example/a")

    def test_percent_encoded_target(self):
        self.assertEqual(
            unwrap_redirect("https://trk.example/?u=https%3A%2F%2Fevil.example%2Fa"),
            "https://evil.example/a")

    def test_linkedin_click_tracker_shape(self):
        self.assertEqual(
            unwrap_redirect("https://www.linkedin.com/e/v2?url=https://linkedinmobileapp.com"),
            "https://linkedinmobileapp.com")

    def test_non_url_or_missing_parameter_returns_none(self):
        self.assertIsNone(unwrap_redirect("https://ok.example/?url=not-a-url"))
        self.assertIsNone(unwrap_redirect("https://ok.example/path"))
        self.assertIsNone(unwrap_redirect("https://ok.example/"))

    def test_malformed_url_returns_none_instead_of_raising(self):
        self.assertIsNone(unwrap_redirect("http://[::1"))


class FromMatchesBrandTests(unittest.TestCase):
    def test_matches(self):
        self.assertTrue(from_matches_brand("paypal", "paypal.com"))
        self.assertTrue(from_matches_brand("paypal", "mail.paypal.com"))

    def test_does_not_match(self):
        self.assertFalse(from_matches_brand("paypal", "paypa1-secure.com"))
        self.assertFalse(from_matches_brand("paypal", ""))
        self.assertFalse(from_matches_brand("", "paypal.com"))
        self.assertFalse(from_matches_brand("nosuchbrand", "nosuchbrand.com"))


class TrustPropagationTests(unittest.TestCase):
    """The LinkedIn false-positive fix: an aligned triple-pass plus a brand
    From domain downgrades a brand-lookalike URL to LOW."""

    LOOKALIKE = "https://linkedin-careers.example/apply"

    def test_downgraded_when_brand_from_domain_and_auth_all_pass(self):
        r = analyze(from_="LinkedIn <no-reply@linkedin.com>", auth_results=ALL_PASS,
                    body=self.LOOKALIKE)
        t = titles(r)
        self.assertIn("Brand-adjacent URL in authenticated brand email", t)
        self.assertNotIn("Link domain imitates a known brand", t)
        finding = next(f for f in r["findings"]
                       if f["title"] == "Brand-adjacent URL in authenticated brand email")
        self.assertEqual(finding["severity"], "LOW")
        self.assertEqual(finding["points"], 3)

    def test_still_high_when_auth_does_not_all_pass(self):
        r = analyze(from_="LinkedIn <no-reply@linkedin.com>",
                    auth_results="spf=pass smtp.mailfrom=no-reply@linkedin.com; "
                                 "dkim=pass header.d=linkedin.com; dmarc=fail",
                    body=self.LOOKALIKE)
        t = titles(r)
        self.assertIn("Link domain imitates a known brand", t)
        self.assertNotIn("Brand-adjacent URL in authenticated brand email", t)

    def test_still_high_when_from_domain_is_not_the_brand(self):
        r = analyze(from_="LinkedIn <no-reply@evil.example>",
                    auth_results="spf=pass smtp.mailfrom=no-reply@evil.example; "
                                 "dkim=pass header.d=evil.example; dmarc=pass",
                    body=self.LOOKALIKE)
        self.assertIn("Link domain imitates a known brand", titles(r))

    def test_auth_aware_downgrade_not_applied_to_sender_lookalike(self):
        """The header lookalike rule is independent of URL trust."""
        r = analyze(from_="LinkedIn <no-reply@linkedin-secure.example>",
                    auth_results="spf=pass smtp.mailfrom=a@linkedin-secure.example; "
                                 "dkim=pass header.d=linkedin-secure.example; dmarc=pass",
                    body="https://ok.example/")
        self.assertIn("Lookalike / typosquatted sender domain", titles(r))


class RedirectTargetCheckedTests(unittest.TestCase):
    def test_unwrapped_target_is_analysed(self):
        r = analyze(body="https://www.linkedin.com/e/v2?url=http://45.133.1.77/login")
        self.assertIn("URL uses a raw IP address", titles(r))
        self.assertIn("45.133.1.77", " ".join(r["iocs"]["urls"]))

    def test_unwrapped_target_detail_is_labelled(self):
        r = analyze(body="https://ok.example/?url=http://45.133.1.77/login")
        finding = next(f for f in r["findings"] if f["title"] == "URL uses a raw IP address")
        self.assertTrue(finding["detail"].startswith("[unwrapped target] "))

    def test_anchor_mismatch_not_reported_against_unwrapped_target(self):
        """The visible text is compared to the wrapper, not the inner target."""
        html = '<a href="https://www.linkedin.com/e/v2?url=https://evil.example/a">https://linkedin.com</a>'
        r = analyze(from_="LinkedIn <no-reply@linkedin.com>", auth_results=ALL_PASS, html=html)
        self.assertNotIn("Link text does not match link target", titles(r))


def fake_dns(records):
    """Install a stub dns.resolver returning canned TXT records."""
    dns = types.ModuleType("dns")
    resolver = types.ModuleType("dns.resolver")

    class Answer:
        def __init__(self, text):
            self.strings = [text.encode()]

    def resolve(name, rdtype, lifetime=None):
        return [Answer(t) for t in records.get(name, [])]

    resolver.resolve = resolve
    dns.resolver = resolver
    return mock.patch.dict(sys.modules, {"dns": dns, "dns.resolver": resolver})


class DnsTests(unittest.TestCase):
    RAW = eml(from_="Test <t@nosuchdomain.example>", return_path="b@nosuchdomain.example")

    def test_missing_spf_and_dmarc_reported(self):
        with fake_dns({}):
            r = PhishingAnalyzer(self.RAW, use_dns=True).analyze()
        t = titles(r)
        self.assertIn("No SPF record published for nosuchdomain.example", t)
        self.assertIn("No DMARC record published for nosuchdomain.example", t)

    def test_records_stored_in_meta(self):
        records = {"nosuchdomain.example": ["v=spf1 -all"],
                   "_dmarc.nosuchdomain.example": ["v=DMARC1; p=reject"]}
        with fake_dns(records):
            r = PhishingAnalyzer(self.RAW, use_dns=True).analyze()
        self.assertEqual(r["meta"]["dns"]["domain"], "nosuchdomain.example")
        self.assertEqual(r["meta"]["dns"]["spf"], ["v=spf1 -all"])
        self.assertEqual(r["meta"]["dns"]["dmarc"], ["v=DMARC1; p=reject"])
        self.assertNotIn("No SPF record published for nosuchdomain.example", titles(r))

    def test_dmarc_p_none_flagged(self):
        records = {"nosuchdomain.example": ["v=spf1 -all"],
                   "_dmarc.nosuchdomain.example": ["v=DMARC1; p=none"]}
        with fake_dns(records):
            r = PhishingAnalyzer(self.RAW, use_dns=True).analyze()
        self.assertIn("DMARC policy for nosuchdomain.example is p=none", titles(r))

    def test_dns_not_run_without_the_flag(self):
        with fake_dns({}):
            r = PhishingAnalyzer(self.RAW).analyze()
        self.assertNotIn("dns", r["meta"])

    def test_skipped_when_dnspython_missing(self):
        with mock.patch.dict(sys.modules, {"dns": None}):
            r = PhishingAnalyzer(self.RAW, use_dns=True).analyze()
        self.assertIn("DNS checks skipped", titles(r))

    def test_no_from_domain_is_a_no_op(self):
        with fake_dns({}):
            r = PhishingAnalyzer(eml(from_=None), use_dns=True).analyze()
        self.assertNotIn("dns", r["meta"])


class PrintReportTests(unittest.TestCase):
    def render(self, **kwargs):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(analyze(**kwargs))
        return buf.getvalue()

    def test_core_fields_rendered(self):
        out = self.render(from_="PayPal Support <x@evil.example>",
                          subject="URGENT verify", auth_results="spf=fail; dmarc=fail")
        self.assertIn("PHISHING EMAIL ANALYSIS REPORT", out)
        self.assertIn("Verdict", out)
        self.assertIn("Risk score", out)
        self.assertIn("URGENT verify", out)
        self.assertIn("SPF: fail", out)
        self.assertIn("DMARC: fail", out)
        self.assertIn("MITRE ATT&CK", out)

    def test_missing_optional_headers_render_as_dash(self):
        out = self.render(return_path=None, reply_to=None)
        self.assertIn("Return-Path: -", out)
        self.assertIn("Origin IP  : -", out)

    def test_ioc_sections_rendered(self):
        out = self.render(body="http://45.133.1.77/x",
                          attachments=[("a.exe", b"MZ", "application/octet-stream")])
        self.assertIn("Domains:", out)
        self.assertIn("IPs:", out)
        self.assertIn("URLs:", out)
        self.assertIn("Attachments:", out)
        self.assertIn("45[.]133[.]1[.]77", out)

    def test_raw_ip_host_is_listed_as_ip_not_domain(self):
        report = analyze(body="http://45.133.1.77/x")
        self.assertIn("45.133.1.77", report["iocs"]["ips"])
        self.assertNotIn("45.133.1.77", report["iocs"]["domains"])

    def test_urls_are_defanged_in_output(self):
        out = self.render(body="https://evil.example/login")
        self.assertIn("hxxps://evil[.]example", out)
        self.assertNotIn("https://evil.example", out)

    def test_works_on_empty_message(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(PhishingAnalyzer(b"").analyze())
        self.assertIn("Verdict", buf.getvalue())


class CliTests(unittest.TestCase):
    SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

    def run_cli(self, argv):
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["analyzer.py"] + argv):
            with contextlib.redirect_stdout(buf):
                analyzer.main()
        return buf.getvalue()

    def test_analyze_sample(self):
        out = self.run_cli([os.path.join(self.SAMPLES, "phish_paypal.eml")])
        self.assertIn("PHISHING EMAIL ANALYSIS REPORT", out)
        self.assertIn("100/100", out)

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "report.json")
            self.run_cli([os.path.join(self.SAMPLES, "phish_paypal.eml"), "--json", dest])
            with open(dest, encoding="utf-8") as fh:
                report = json.load(fh)
        self.assertEqual(report["verdict"], "PHISHING (high confidence)")
        self.assertEqual(report["risk_score"], 100)
        for key in ("verdict", "risk_score", "meta", "authentication", "findings",
                    "mitre_techniques", "iocs"):
            self.assertIn(key, report)

    def test_json_export_is_serialisable_with_sorted_iocs(self):
        with tempfile.TemporaryDirectory() as d:
            dest = os.path.join(d, "report.json")
            self.run_cli([os.path.join(self.SAMPLES, "phish_invoice.eml"), "--json", dest])
            with open(dest, encoding="utf-8") as fh:
                report = json.load(fh)
        for key in ("domains", "ips", "urls", "emails"):
            self.assertEqual(report["iocs"][key], sorted(report["iocs"][key]))
        self.assertEqual(len(report["iocs"]["hashes"]), 1)

    def test_committed_sample_report_matches_current_output(self):
        """report_phish_paypal.json must not drift from what the tool produces."""
        committed_path = os.path.join(self.SAMPLES, "..", "report_phish_paypal.json")
        with open(committed_path, encoding="utf-8") as fh:
            committed = json.load(fh)
        with open(os.path.join(self.SAMPLES, "phish_paypal.eml"), "rb") as fh:
            fresh = PhishingAnalyzer(fh.read()).analyze()
        for r in (committed, fresh):
            r["meta"].pop("date", None)
        self.assertEqual(committed, fresh)

    def test_missing_file_exits_with_message(self):
        with mock.patch.object(sys, "argv", ["analyzer.py", "does_not_exist.eml"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    analyzer.main()
        self.assertIn("Cannot read", str(ctx.exception))

    def test_dns_flag_accepted(self):
        out = self.run_cli([os.path.join(self.SAMPLES, "legit_github.eml"), "--dns"])
        self.assertIn("LOW RISK", out)


class BodyExtractionRobustnessTests(unittest.TestCase):
    def test_non_text_parts_are_skipped(self):
        r = analyze(body="hello",
                    attachments=[("logo.png", b"\x89PNG", "image/png")])
        self.assertIn("verdict", r)

    def test_undecodable_text_part_does_not_abort(self):
        """A part that cannot be decoded must be skipped, not kill the report."""
        raw = (b"From: Test <t@example.com>\r\nSubject: t\r\n"
               b"Date: Tue, 29 Sep 2026 10:00:00 +0000\r\n"
               b"Message-ID: <a@example.com>\r\n"
               b"MIME-Version: 1.0\r\n"
               b'Content-Type: text/plain; charset="utf-8"\r\n'
               b"Content-Transfer-Encoding: 8bit\r\n\r\n"
               b"valid text \xff\xfe\xfd invalid utf-8 and https://evil.example/x\r\n")
        report = PhishingAnalyzer(raw).analyze()
        self.assertIn("verdict", report)

    def test_unknown_charset_part_does_not_abort(self):
        raw = (b"From: Test <t@example.com>\r\nSubject: t\r\n"
               b"Date: Tue, 29 Sep 2026 10:00:00 +0000\r\n"
               b"Message-ID: <a@example.com>\r\n"
               b"MIME-Version: 1.0\r\n"
               b'Content-Type: text/plain; charset="x-not-a-real-charset"\r\n\r\n'
               b"body text\r\n")
        report = PhishingAnalyzer(raw).analyze()
        self.assertIn("verdict", report)

    def test_html_and_attachment_multipart_is_walked(self):
        raw = eml(html='<a href="https://paypa1-secure.com/a">click</a>',
                  attachments=[("x.exe", b"MZ", "application/octet-stream")])
        r = PhishingAnalyzer(raw).analyze()
        t = titles(r)
        self.assertIn("Link domain imitates a known brand", t)
        self.assertIn("Executable/script attachment (.exe)", t)
        self.assertIn("https://paypa1-secure.com/a", r["iocs"]["urls"])

    def test_plain_and_html_both_analysed_in_alternative(self):
        raw = eml(body="see https://raw-ip.example/a",
                  html='<a href="https://paypa1-secure.com/a">click</a>')
        r = PhishingAnalyzer(raw).analyze()
        self.assertIn("https://raw-ip.example/a", r["iocs"]["urls"])
        self.assertIn("https://paypa1-secure.com/a", r["iocs"]["urls"])


if __name__ == "__main__":
    unittest.main()
