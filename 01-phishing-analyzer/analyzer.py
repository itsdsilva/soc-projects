#!/usr/bin/env python3
"""
Phishing Email Analyzer
=======================
Analyzes a .eml file for phishing indicators:
  * Header analysis (From / Reply-To / Return-Path / Message-ID / Received chain)
  * SPF / DKIM / DMARC results (from Authentication-Results) + alignment checks
  * Optional live DNS lookup of the sender's SPF / DMARC records (--dns)
  * URL analysis (anchor/href mismatch, IP hosts, shorteners, punycode, lookalikes)
  * Attachment analysis (hashes, dangerous / double extensions, macros)
  * Weighted risk score, verdict, IOC list and MITRE ATT&CK mapping

Standard library only (dnspython optional for --dns).
Safe by design: never opens links or executes attachments.

Usage:
    python analyzer.py samples/phish_paypal.eml
    python analyzer.py samples/phish_paypal.eml --json report.json
    python analyzer.py samples/phish_paypal.eml --dns
"""
import argparse
import difflib
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Reference data (extend these lists as you learn - it's part of the project)
# --------------------------------------------------------------------------- #
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "github": ["github.com"],
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy"}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml",
                   "cf", "ga", "work", "support", "rest", "monster", "icu", "buzz"}

DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "iso",
                 "img", "bat", "cmd", "ps1", "jar", "msi", "dll", "com", "cpl", "chm", "reg"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab"}
HTML_EXT = {"html", "htm", "svg"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "rtf"}

URGENCY = ["urgent", "immediately", "within 24 hours", "account suspended", "account will be",
           "final notice", "action required", "verify now", "act now", "last warning",
           "limited access", "unusual activity", "security alert"]
CREDENTIAL_BAIT = ["verify your account", "confirm your identity", "update your password",
                   "log in", "login", "sign in", "confirm your payment", "billing information",
                   "reset your password"]

TWO_LEVEL_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "net.in", "org.in",
                  "gov.in", "co.jp", "com.br", "co.za", "com.cn", "co.nz"}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str      # INFO / LOW / MEDIUM / HIGH / CRITICAL
    category: str      # Header / Authentication / URL / Attachment / Content
    title: str
    detail: str
    points: int
    mitre: str = ""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def defang(s: str) -> str:
    """Make URLs / domains safe to paste into tickets and reports."""
    return s.replace("http", "hxxp").replace(".", "[.]")


def base_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def addr_domain(header_value) -> str:
    _, addr = parseaddr(str(header_value or ""))
    return addr.rpartition("@")[2].lower()


def normalize_lookalike(label: str) -> str:
    """Undo common character substitutions: paypa1 -> paypal, rnicrosoft -> microsoft."""
    label = label.lower()
    for a, b in (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")):
        label = label.replace(a, b)
    return label


def check_lookalike(domain: str):
    """Return (brand, reason) if the domain imitates a known brand, else None."""
    base = base_domain(domain)
    if not base:
        return None
    for brand, legit in BRANDS.items():
        if base in legit:
            return None
    label = base.split(".")[0]
    norm = normalize_lookalike(label)
    for brand in BRANDS:
        if brand in label or brand in norm:
            return brand, f"'{base}' contains brand name '{brand}' but is not an official domain"
        ratio = difflib.SequenceMatcher(None, norm, brand).ratio()
        if ratio >= 0.85 and norm != brand:
            return brand, f"'{base}' is a near-match ({ratio:.0%}) to '{brand}' (typosquat)"
    return None


class LinkExtractor(HTMLParser):
    """Collects <a href> targets together with their visible anchor text."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._text).split())))
            self._href = None


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
class PhishingAnalyzer:
    def __init__(self, raw: bytes, use_dns: bool = False):
        self.msg = BytesParser(policy=policy.default).parsebytes(raw)
        self.use_dns = use_dns
        self.findings: list[Finding] = []
        self.iocs = {"domains": set(), "ips": set(), "urls": set(), "emails": set(), "hashes": []}
        self.auth = {"spf": None, "dkim": None, "dmarc": None}
        self.meta = {}

    def add(self, sev, cat, title, detail, pts, mitre=""):
        f = Finding(sev, cat, title, detail, pts, mitre)
        if not any(x.title == f.title and x.detail == f.detail for x in self.findings):
            self.findings.append(f)

    # ------------------------------------------------------------------ #
    def analyze(self) -> dict:
        self.check_headers()
        self.check_authentication()
        self.check_received_chain()
        body_text, links = self.extract_body()
        self.check_urls(links, body_text)
        self.check_attachments()
        self.check_content(body_text)
        if self.use_dns:
            self.check_dns()
        return self.build_report()

    # ------------------------------ headers ---------------------------- #
    def check_headers(self):
        m = self.msg
        from_hdr, reply_to, return_path = m.get("From"), m.get("Reply-To"), m.get("Return-Path")
        from_name, from_addr = parseaddr(str(from_hdr or ""))
        from_dom = addr_domain(from_hdr)
        self.meta = {
            "subject": str(m.get("Subject", "")), "from": str(from_hdr or ""),
            "reply_to": str(reply_to or ""), "return_path": str(return_path or ""),
            "to": str(m.get("To", "")), "date": str(m.get("Date", "")),
            "message_id": str(m.get("Message-ID", "")),
            "x_originating_ip": str(m.get("X-Originating-IP", "")),
        }
        if from_addr:
            self.iocs["emails"].add(from_addr)
        if from_dom:
            self.iocs["domains"].add(from_dom)

        # Reply-To differs from From
        if reply_to:
            rt_dom = addr_domain(reply_to)
            self.iocs["emails"].add(parseaddr(str(reply_to))[1])
            if rt_dom and base_domain(rt_dom) != base_domain(from_dom):
                self.add("HIGH", "Header", "Reply-To domain differs from From",
                         f"From: {from_dom} | Reply-To: {rt_dom} - replies go somewhere else.", 15, "T1566")

        # Return-Path (envelope sender) differs from From
        if return_path:
            rp_dom = addr_domain(return_path)
            if rp_dom:
                self.iocs["domains"].add(rp_dom)
            if rp_dom and base_domain(rp_dom) != base_domain(from_dom):
                self.add("MEDIUM", "Header", "Return-Path domain differs from From",
                         f"Envelope sender {rp_dom} vs visible sender {from_dom}. "
                         "(Common for legit bulk mailers - weigh with SPF/DKIM/DMARC.)", 12, "T1566")

        # Display-name spoofing
        if from_name:
            if "@" in from_name and addr_domain(from_name) != from_dom:
                self.add("HIGH", "Header", "Display name contains a different email address",
                         f"Display name '{from_name}' impersonates another address.", 20, "T1656")
            for brand, legit in BRANDS.items():
                if brand in from_name.lower().replace(" ", "") and base_domain(from_dom) not in legit:
                    self.add("HIGH", "Header", f"Display name impersonates '{brand}'",
                             f"Display name '{from_name}' but sending domain is {from_dom}.", 20, "T1656")
                    break

        # Lookalike sender domain
        hit = check_lookalike(from_dom) if from_dom else None
        if hit:
            self.add("CRITICAL", "Header", "Lookalike / typosquatted sender domain", hit[1], 25, "T1566")

        # Message-ID sanity
        mid = self.meta["message_id"]
        if not mid:
            self.add("LOW", "Header", "Missing Message-ID", "Legitimate MTAs always add one.", 5)
        elif from_dom and "@" in mid:
            mid_dom = mid.strip("<>").rpartition("@")[2].lower()
            if base_domain(mid_dom) != base_domain(from_dom):
                self.add("LOW", "Header", "Message-ID domain differs from From",
                         f"Message-ID domain {mid_dom} vs From {from_dom}.", 5)
        if not m.get("Date"):
            self.add("LOW", "Header", "Missing Date header", "Unusual for legitimate mail.", 3)

    # --------------------------- SPF/DKIM/DMARC ------------------------ #
    def check_authentication(self):
        m = self.msg
        from_dom = addr_domain(m.get("From"))
        ar_headers = [str(h) for h in m.get_all("Authentication-Results", [])]
        details = {"dkim_domain": None, "spf_domain": None}

        for h in ar_headers:
            for mech in self.auth:
                hit = re.search(rf"\b{mech}=(\w+)", h, re.I)
                if hit and self.auth[mech] is None:
                    self.auth[mech] = hit.group(1).lower()
            d = re.search(r"header\.d=([\w.\-]+)", h, re.I)
            if d and not details["dkim_domain"]:
                details["dkim_domain"] = d.group(1).lower()
            s = re.search(r"smtp\.mailfrom=(?:[\w.+\-]*@)?([\w.\-]+)", h, re.I)
            if s and not details["spf_domain"]:
                details["spf_domain"] = s.group(1).lower()

        rspf = m.get("Received-SPF")
        if self.auth["spf"] is None and rspf:
            hit = re.match(r"\s*(\w+)", str(rspf))
            if hit:
                self.auth["spf"] = hit.group(1).lower()

        if not ar_headers and not rspf:
            self.add("LOW", "Authentication", "No Authentication-Results header",
                     "Cannot confirm SPF/DKIM/DMARC. Pull the original from the mail gateway.", 5)
            return

        spf, dkim, dmarc = self.auth["spf"], self.auth["dkim"], self.auth["dmarc"]
        if spf in ("fail", "hardfail"):
            self.add("HIGH", "Authentication", "SPF FAIL",
                     "Sending IP is not authorized by the envelope domain.", 20, "T1566")
        elif spf in ("softfail", "permerror", "temperror"):
            self.add("MEDIUM", "Authentication", f"SPF {spf.upper()}", "Weak / broken SPF result.", 10, "T1566")
        elif spf in ("none", "neutral"):
            self.add("LOW", "Authentication", f"SPF {spf.upper()}", "No SPF policy asserted.", 5)

        if dkim == "fail":
            self.add("HIGH", "Authentication", "DKIM FAIL", "Signature invalid - message may be forged or modified.", 15, "T1566")
        elif dkim in ("none", None):
            self.add("LOW", "Authentication", "No DKIM signature", "Message is unsigned.", 5)
        elif dkim == "pass" and details["dkim_domain"] and from_dom and \
                base_domain(details["dkim_domain"]) != base_domain(from_dom):
            self.add("MEDIUM", "Authentication", "DKIM passes but is NOT aligned with From",
                     f"Signed by {details['dkim_domain']}, From is {from_dom}. Attackers often sign with their own domain.", 8)

        if spf == "pass" and details["spf_domain"] and from_dom and \
                base_domain(details["spf_domain"]) != base_domain(from_dom):
            self.add("MEDIUM", "Authentication", "SPF passes but is NOT aligned with From",
                     f"SPF checked {details['spf_domain']}, From is {from_dom}. Passing SPF for a domain the attacker owns proves little.", 8)

        if dmarc == "fail":
            self.add("CRITICAL", "Authentication", "DMARC FAIL",
                     "Neither aligned SPF nor aligned DKIM passed for the From domain.", 25, "T1566")
        elif dmarc in ("none", None):
            self.add("LOW", "Authentication", "No DMARC result", "From domain may have no DMARC policy.", 3)

    # ---------------------------- Received chain ----------------------- #
    def check_received_chain(self):
        received = [str(r) for r in self.msg.get_all("Received", [])]
        self.meta["hops"] = len(received)
        origin = None
        for hop in reversed(received):                 # last header = first hop
            for ip in re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", hop):
                try:
                    if ipaddress.ip_address(ip).is_global:
                        origin = ip
                        break
                except ValueError:
                    continue
            if origin:
                break
        self.meta["origin_ip"] = origin
        if origin:
            self.iocs["ips"].add(origin)
        xo = self.meta.get("x_originating_ip", "").strip("[] ")
        if xo:
            self.iocs["ips"].add(xo)
        if len(received) == 0:
            self.add("LOW", "Header", "No Received headers", "Headers may have been stripped or forged.", 5)

    # ------------------------------- body ------------------------------ #
    def extract_body(self):
        text_parts, links = [], []
        for part in self.msg.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/html":
                parser = LinkExtractor()
                parser.feed(content)
                links.extend(parser.links)
                text_parts.append(re.sub(r"<[^>]+>", " ", content))
            else:
                text_parts.append(content)
                for u in re.findall(r"https?://[^\s<>\"')\]]+", content):
                    links.append((u, ""))
        return " ".join(text_parts), links

    # -------------------------------- URLs ----------------------------- #
    def check_urls(self, links, body_text):
        seen = set()
        for href, text in links:
            if not href.lower().startswith(("http://", "https://")) or href in seen:
                continue
            seen.add(href)
            self.iocs["urls"].add(href)
            u = urlparse(href)
            host = (u.hostname or "").lower()
            self.iocs["domains"].add(host)
            shown = defang(href)

            # Anchor text says one thing, href goes elsewhere
            m = re.search(r"((?:https?://)?(?:[\w\-]+\.)+[a-z]{2,})", text.lower())
            if m:
                text_host = urlparse(m.group(1) if "//" in m.group(1) else "//" + m.group(1)).hostname or ""
                if base_domain(text_host) != base_domain(host):
                    self.add("CRITICAL", "URL", "Link text does not match link target",
                             f"Displays '{text_host}' but goes to {shown}", 25, "T1566.002")

            try:
                ipaddress.ip_address(host)
                self.add("HIGH", "URL", "URL uses a raw IP address", shown, 20, "T1566.002")
            except ValueError:
                pass
            if base_domain(host) in URL_SHORTENERS:
                self.add("MEDIUM", "URL", "URL shortener hides destination", shown, 8, "T1566.002")
            if "xn--" in host:
                self.add("HIGH", "URL", "Punycode (IDN homograph) domain", shown, 15, "T1566.002")
            if host.rpartition(".")[2] in SUSPICIOUS_TLDS:
                self.add("MEDIUM", "URL", f"Suspicious TLD .{host.rpartition('.')[2]}", shown, 8, "T1566.002")
            if u.username:
                self.add("HIGH", "URL", "Credentials/@ trick in URL", shown, 15, "T1566.002")
            if u.scheme == "http":
                self.add("LOW", "URL", "Unencrypted HTTP link", shown, 3)
            if host.count(".") >= 4:
                self.add("LOW", "URL", "Excessive subdomains", shown, 4)
            hit = check_lookalike(host)
            if hit:
                self.add("HIGH", "URL", "Link domain imitates a known brand", f"{hit[1]} ({shown})", 20, "T1566.002")

    # ----------------------------- attachments ------------------------- #
    def check_attachments(self):
        for part in self.msg.walk():
            name = part.get_filename()
            if not name:
                continue
            data = part.get_payload(decode=True) or b""
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            self.iocs["hashes"].append({"file": name, "size": len(data), "sha256": sha256, "md5": md5})

            parts = name.lower().split(".")
            ext = parts[-1] if len(parts) > 1 else ""
            note = f"{name} ({len(data)} bytes, sha256 {sha256[:16]}...)"

            if len(parts) > 2 and parts[-2] in DOC_EXT and ext in DANGEROUS_EXT:
                self.add("CRITICAL", "Attachment", "Double extension (masquerading)", note, 35, "T1036.007")
            elif ext in DANGEROUS_EXT:
                self.add("CRITICAL", "Attachment", f"Executable/script attachment (.{ext})", note, 30, "T1566.001")
            elif ext in MACRO_EXT:
                self.add("HIGH", "Attachment", f"Macro-enabled Office file (.{ext})", note, 20, "T1566.001")
            elif ext in HTML_EXT:
                self.add("HIGH", "Attachment", "HTML attachment (possible HTML smuggling / fake login page)", note, 15, "T1566.001")
            elif ext in ARCHIVE_EXT:
                self.add("MEDIUM", "Attachment", f"Archive attachment (.{ext})", note + " - archives can hide payloads from scanners.", 8, "T1566.001")
            if re.search(r"[\u202e]", name):
                self.add("CRITICAL", "Attachment", "Right-to-left override in filename", repr(name), 30, "T1036.002")

    # ------------------------------ content ---------------------------- #
    def check_content(self, body_text):
        low = body_text.lower()
        urg = [k for k in URGENCY if k in low]
        bait = [k for k in CREDENTIAL_BAIT if k in low]
        if len(urg) >= 2:
            self.add("MEDIUM", "Content", "Urgency / pressure language", ", ".join(urg[:5]), 8, "T1566")
        if bait:
            self.add("LOW", "Content", "Credential-harvesting language", ", ".join(bait[:5]), 5, "T1566")
        if "password" in low and any(k in low for k in ("zip", "archive", "attached")):
            self.add("LOW", "Content", "Password mentioned alongside attachment",
                     "Password-protected archives are a classic scanner-evasion trick.", 5)

    # -------------------------------- DNS ------------------------------ #
    def check_dns(self):
        try:
            import dns.resolver
        except ImportError:
            self.add("INFO", "Authentication", "DNS checks skipped", "pip install dnspython to enable --dns.", 0)
            return
        dom = base_domain(addr_domain(self.msg.get("From")))
        if not dom:
            return

        def txt(name):
            try:
                return ["".join(s.decode() for s in r.strings) for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
            except Exception:
                return []

        spf = [t for t in txt(dom) if t.lower().startswith("v=spf1")]
        dmarc = [t for t in txt(f"_dmarc.{dom}") if t.lower().startswith("v=dmarc1")]
        self.meta["dns"] = {"domain": dom, "spf": spf, "dmarc": dmarc}
        if not spf:
            self.add("MEDIUM", "Authentication", f"No SPF record published for {dom}",
                     "Domain is trivially spoofable.", 10)
        if not dmarc:
            self.add("MEDIUM", "Authentication", f"No DMARC record published for {dom}",
                     "Receivers have no policy to enforce against spoofing.", 8)
        elif re.search(r"p=none", dmarc[0], re.I):
            self.add("LOW", "Authentication", f"DMARC policy for {dom} is p=none",
                     "Monitoring only - spoofed mail is still delivered.", 3)

    # ------------------------------- report ---------------------------- #
    def build_report(self) -> dict:
        score = min(100, sum(f.points for f in self.findings))
        if score >= 75:
            verdict = "PHISHING (high confidence)"
        elif score >= 50:
            verdict = "LIKELY PHISHING"
        elif score >= 20:
            verdict = "SUSPICIOUS - manual review"
        else:
            verdict = "LOW RISK"
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings = sorted(self.findings, key=lambda f: (order[f.severity], -f.points))
        techniques = sorted({t for f in findings for t in f.mitre.split(",") if t})
        return {
            "verdict": verdict, "risk_score": score, "meta": self.meta,
            "authentication": self.auth,
            "findings": [asdict(f) for f in findings],
            "mitre_techniques": techniques,
            "iocs": {
                "domains": sorted(d for d in self.iocs["domains"] if d),
                "ips": sorted(self.iocs["ips"]),
                "urls": sorted(self.iocs["urls"]),
                "emails": sorted(e for e in self.iocs["emails"] if e),
                "hashes": self.iocs["hashes"],
            },
        }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(r: dict):
    m, a = r["meta"], r["authentication"]
    bar = "=" * 70
    print(bar)
    print(" PHISHING EMAIL ANALYSIS REPORT")
    print(bar)
    print(f" Verdict    : {r['verdict']}")
    print(f" Risk score : {r['risk_score']}/100")
    print(f" Subject    : {m['subject']}")
    print(f" From       : {m['from']}")
    if m["reply_to"]:
        print(f" Reply-To   : {m['reply_to']}")
    print(f" Return-Path: {m['return_path'] or '-'}")
    print(f" To         : {m['to']}")
    print(f" Date       : {m['date']}")
    print(f" Origin IP  : {defang(m.get('origin_ip') or '-')}  ({m.get('hops', 0)} hops)")
    print("-" * 70)
    print(f" SPF: {a['spf'] or 'n/a'}   DKIM: {a['dkim'] or 'n/a'}   DMARC: {a['dmarc'] or 'n/a'}")
    print("-" * 70)
    print(f" FINDINGS ({len(r['findings'])})")
    for f in r["findings"]:
        tag = f"[{f['severity']}]".ljust(10)
        print(f"  {tag} {f['title']}  (+{f['points']})")
        print(f"             {f['detail']}")
    print("-" * 70)
    print(" IOCs")
    for label, key in (("Domains", "domains"), ("IPs", "ips"), ("URLs", "urls"), ("Emails", "emails")):
        vals = r["iocs"][key]
        if vals:
            print(f"  {label}:")
            for v in vals:
                print(f"    - {defang(v)}")
    if r["iocs"]["hashes"]:
        print("  Attachments:")
        for h in r["iocs"]["hashes"]:
            print(f"    - {h['file']}  SHA256 {h['sha256']}")
    print("-" * 70)
    print(f" MITRE ATT&CK: {', '.join(r['mitre_techniques']) or '-'}")
    print(bar)


def main():
    ap = argparse.ArgumentParser(description="Phishing Email Analyzer (.eml)")
    ap.add_argument("eml", help="path to .eml file")
    ap.add_argument("--json", metavar="FILE", help="also write the full report as JSON")
    ap.add_argument("--dns", action="store_true", help="look up sender SPF/DMARC records (needs dnspython)")
    args = ap.parse_args()

    try:
        with open(args.eml, "rb") as fh:
            raw = fh.read()
    except OSError as e:
        sys.exit(f"Cannot read {args.eml}: {e}")

    report = PhishingAnalyzer(raw, use_dns=args.dns).analyze()
    print_report(report)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f" JSON report written to {args.json}")


if __name__ == "__main__":
    main()
