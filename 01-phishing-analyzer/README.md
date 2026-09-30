# 01 - Phishing Email Analyzer

A Python tool that analyzes `.eml` files and answers the question a SOC analyst asks
on every reported email: **"Is this phishing, and why?"**

It checks **email headers, SPF/DKIM/DMARC, URLs and attachments**, produces a weighted
risk score, extracts **defanged IOCs**, and maps findings to **MITRE ATT&CK**.

> Safe by design: the tool never opens links or executes attachments. It only parses and hashes.

## Features

| Area | What is checked |
|---|---|
| Headers | From vs Reply-To vs Return-Path mismatch, display-name spoofing, lookalike / typosquat sender domain, Message-ID mismatch, missing headers, origin IP from `Received` chain |
| Authentication | SPF, DKIM, DMARC results from `Authentication-Results`, **alignment** checks (a pass on an attacker's own domain is flagged), optional live DNS lookup of SPF/DMARC records (`--dns`) |
| URLs | Anchor text vs real `href`, raw IP hosts, URL shorteners, punycode, suspicious TLDs, `user@host` tricks, brand lookalikes, plain HTTP |
| Attachments | SHA256/MD5, double extensions (`invoice.pdf.exe`), executables/scripts, macro Office files, HTML smuggling, archives, RTL-override filenames |
| Content | Urgency language, credential-harvesting phrases |
| Output | Console report, JSON (`--json`), defanged IOCs, MITRE technique list |

## Quick start

```bash
git clone <your-repo> && cd phishing-analyzer
python analyzer.py samples/phish_paypal.eml
python analyzer.py samples/phish_paypal.eml --json report.json
pip install dnspython && python analyzer.py samples/phish_paypal.eml --dns   # optional
python -m unittest discover -s tests -v
```

No dependencies required (standard library only). Python 3.9+.

### Getting a real .eml
- **Gmail:** open message → ⋮ → *Download message*
- **Outlook:** drag the message to your desktop, or *File → Save As → .eml* (classic)
- **Thunderbird:** right-click → *Save As*

## Sample results

| Sample | SPF / DKIM / DMARC | Score | Verdict | Why |
|---|---|---|---|---|
| `phish_paypal.eml` | fail / none / fail | 100 | Phishing | Typosquat `paypa1-secure.com`, DMARC fail, Reply-To to Gmail, link text says paypal.com but goes elsewhere, raw-IP link |
| `phish_invoice.eml` | **pass / pass / pass** | 93 | Phishing | Auth passes because the attacker owns the domain, but `Invoice_9931.pdf.exe`, DHL impersonation and urgency give it away |
| `legit_github.eml` | pass / pass / pass | 0 | Low risk | Everything aligned |

The second sample is the important one: **passing SPF/DKIM/DMARC does not mean an email is safe.**
It only proves the sender controls the domain they used.

<details><summary>Example console output (phish_paypal.eml)</summary>

```
 Verdict    : PHISHING (high confidence)
 Risk score : 100/100
 From       : PayPal Support <support@paypa1-secure.com>
 Reply-To   : recovery.desk@gmail.com
 Return-Path: <bounce@mailer-xk3.ru>
 Origin IP  : 45[.]133[.]1[.]77  (2 hops)
 SPF: fail   DKIM: none   DMARC: fail
 FINDINGS (16)
  [CRITICAL] Lookalike / typosquatted sender domain  (+25)
  [CRITICAL] DMARC FAIL  (+25)
  [CRITICAL] Link text does not match link target  (+25)
             Displays 'www.paypal.com' but goes to hxxp://paypa1-secure[.]com[.]account-verify[.]top/login
  [HIGH]     Display name impersonates 'paypal'  (+20)
  [HIGH]     SPF FAIL  (+20)
  ...
 MITRE ATT&CK: T1566, T1566.002, T1656
```
</details>

## How scoring works

Each finding adds points (Critical 25-35, High 15-20, Medium 8-12, Low 3-5). The total is capped at 100.

| Score | Verdict |
|---|---|
| 0-19 | Low risk |
| 20-49 | Suspicious, manual review |
| 50-74 | Likely phishing |
| 75-100 | Phishing (high confidence) |

Weights are deliberately simple and live next to each check in `analyzer.py`, so they are easy to tune.

## MITRE ATT&CK mapping

| Technique | Detected by |
|---|---|
| T1566 Phishing | Header / auth anomalies |
| T1566.001 Spearphishing Attachment | Dangerous, macro, HTML, archive attachments |
| T1566.002 Spearphishing Link | Mismatched, IP, shortened, punycode, lookalike URLs |
| T1656 Impersonation | Display-name / brand spoofing |
| T1036.007 / T1036.002 Masquerading | Double extension, RTL override |

## False positives and tuning

- **Bulk mailers (Mailchimp, SendGrid, Salesforce):** Return-Path and DKIM domains legitimately differ from From. Alone these score low (12 and 8), so they will not cross the "likely phishing" line.
- **Brand detection** flags any non-official domain containing a brand name, including your own partners (e.g. `paypal-integration.yourcompany.com`). Add trusted domains to `BRANDS`.
- **Shorteners and `.support`/`.xyz` TLDs** appear in legitimate marketing mail. They add small scores only.
- **Missing Authentication-Results** usually means you exported the mail from a client rather than the gateway, so the auth verdict is unknown, not clean.
- Extend `BRANDS`, `SUSPICIOUS_TLDS`, and `DANGEROUS_EXT` for your organization.

## Analyst response playbook

When this tool (or a user report) flags an email:

1. **Contain:** search the mail platform for the same sender, subject, or URL and purge from all mailboxes.
2. **Scope:** who received it? Who clicked? (proxy/DNS logs for the defanged URLs)
3. **Block:** sender domain, Return-Path domain, URLs and IPs at the gateway / proxy / DNS.
4. **Attachment opened?** Look for the SHA256 in EDR, then check for follow-on activity (PowerShell, credential dumping, persistence). These are the detections in projects 3-8.
5. **Credentials entered?** Force password reset, revoke sessions and tokens, review MFA changes and inbox rules.
6. **Report and document:** record IOCs and technique mapping (feeds project 10), notify the user, and consider DMARC policy improvements.

## Project structure

```
phishing-analyzer/
├── analyzer.py               # the tool
├── samples/                  # 2 phishing + 1 legitimate test emails (synthetic)
├── tests/test_analyzer.py    # unit tests
├── report_phish_paypal.json  # sample JSON output
└── README.md
```

All sample emails are synthetic. The attachment is a harmless text blob with an `.exe` name.

## Roadmap / ideas

- [ ] VirusTotal enrichment of URLs and hashes (this becomes project 02)
- [ ] Parse `.msg` files and QR codes in images (quishing)
- [ ] WHOIS domain-age check (newly registered domains are a strong signal)
- [ ] Export a Sigma rule / SIEM query for the top indicators
- [ ] HTML report output

## Skills demonstrated

Email protocol internals (RFC 5322, SPF, DKIM, DMARC), header forensics, threat-indicator extraction and defanging, MITRE ATT&CK mapping, Python parsing, unit testing, and IR playbook writing.
