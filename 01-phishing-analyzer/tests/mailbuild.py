"""Helpers for building synthetic .eml bytes in tests.

Every test constructs exactly the header or body it needs to exercise one
detection, so a failure points at a single check. Part nesting follows RFC
2046 (mixed wrapping alternative when attachments are present) so the parser
under test sees a well-formed message.
"""
import base64

DEFAULT_DATE = "Tue, 29 Sep 2026 10:00:00 +0000"
ALL_PASS = ("spf=pass smtp.mailfrom=noreply@example.com; "
            "dkim=pass header.i=@example.com header.d=example.com; "
            "dmarc=pass header.from=example.com")

_counter = [0]


def _boundary():
    _counter[0] += 1
    return f"BOUNDARY{_counter[0]}"


def _part(content_type, text):
    return f"Content-Type: {content_type}\r\n\r\n{text}"


def _multipart(boundary, parts):
    return "".join(f"--{boundary}\r\n{p}\r\n" for p in parts) + f"--{boundary}--\r\n"


def _text_parts(body, html):
    """Return complete part strings covering the text bodies."""
    if body and html:
        b = _boundary()
        inner = _multipart(b, [_part('text/plain; charset="utf-8"', body),
                               _part('text/html; charset="utf-8"', html)])
        return [f'Content-Type: multipart/alternative; boundary="{b}"\r\n\r\n{inner}']
    if html:
        return [_part('text/html; charset="utf-8"', html)]
    return [_part('text/plain; charset="utf-8"', body or "")]


def _attachment_part(name, data, ctype):
    if isinstance(data, str):
        data = data.encode("utf-8")
    b64 = base64.encodebytes(data).decode("ascii").strip()
    quoted = f'"{name}"' if any(ord(c) > 127 for c in name) else name
    return (f"Content-Type: {ctype}; name={quoted}\r\n"
            f"Content-Disposition: attachment; filename={quoted}\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}")


def eml(from_="Test <t@example.com>", to="v@example.com", subject="t",
        date=DEFAULT_DATE, message_id="<a@example.com>", return_path=None,
        reply_to=None, received=None, auth_results=None, received_spf=None,
        x_originating_ip=None, body="", html=None, attachments=()):
    """Return raw .eml bytes.

    auth_results is the raw Authentication-Results value, e.g. "spf=fail; dmarc=fail".
    attachments is a sequence of (filename, data, content_type).
    """
    h = []
    if return_path:
        h.append(f"Return-Path: <{return_path}>")
    for r in (received or []):
        h.append(f"Received: {r}")
    if x_originating_ip:
        h.append(f"X-Originating-IP: {x_originating_ip}")
    if auth_results:
        h.append(f"Authentication-Results: mx.example.com; {auth_results}")
    if received_spf:
        h.append(f"Received-SPF: {received_spf}")
    if from_:
        h.append(f"From: {from_}")
    if reply_to:
        h.append(f"Reply-To: {reply_to}")
    if to:
        h.append(f"To: {to}")
    if subject:
        h.append(f"Subject: {subject}")
    if date:
        h.append(f"Date: {date}")
    if message_id:
        h.append(f"Message-ID: {message_id}")
    h.append("MIME-Version: 1.0")

    attachments = list(attachments)
    if attachments:
        b = _boundary()
        parts = _text_parts(body, html) + [_attachment_part(n, d, c) for n, d, c in attachments]
        h.append(f'Content-Type: multipart/mixed; boundary="{b}"')
        payload = _multipart(b, parts)
    else:
        parts = _text_parts(body, html)
        if len(parts) == 1 and parts[0].startswith("Content-Type: text/"):
            ctype, _, bodytext = parts[0].partition("\r\n\r\n")
            h.append(ctype)
            payload = bodytext
        else:
            b = _boundary()
            h.append(f'Content-Type: multipart/alternative; boundary="{b}"')
            payload = _multipart(b, parts)

    head = "\r\n".join(h) + "\r\n\r\n"
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return head.encode("utf-8") + payload


def titles(report):
    return [f["title"] for f in report["findings"]]


def analyze(**kwargs):
    from analyzer import PhishingAnalyzer
    return PhishingAnalyzer(eml(**kwargs)).analyze()
