"""Unsubscribe from a bulk sender, the way its mail says to (RFC 2369 / RFC 8058).

The newest message from the sender is read for its List-Unsubscribe header, then:
  one-click   List-Unsubscribe-Post: List-Unsubscribe=One-Click with an https link: POST to it
  email       a mailto: address: send the unsubscribe email from that account (SMTP over SSL
              on the IMAP host's smtp. twin, or the account's `smtp_host`)
  link        only an https page: returned for the owner to open (it may need a click there)

The server only ever contacts public https addresses, never one that resolves to a private or
local network, and follows no redirects (a sender's header must not reach inside the network).
Phishing senders are refused: unsubscribing from them only confirms the address is read.
Each unsubscribe is recorded in the `unsubscribed` table.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import smtplib
import socket
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.parser import BytesHeaderParser
from urllib.parse import parse_qs, unquote, urlparse

log = logging.getLogger("unsubscribe")
SENDER = re.compile(r"[^\s<>@\"()\\,;:]{1,200}@[A-Za-z0-9.-]{1,200}")
HEADERS = b"BODY[HEADER.FIELDS (LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST DATE)]"


class UnsubError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def check_sender(sender):
    if not isinstance(sender, str) or not SENDER.fullmatch(sender):
        raise UnsubError(400, "not an email address")
    return sender.lower()


def options(raw_headers: bytes) -> dict:
    """{"https": [...], "mailto": [...], "one_click": bool} from a message's headers."""
    h = BytesHeaderParser().parsebytes(raw_headers)
    links = re.findall(r"<\s*([^<>\s]+)\s*>", " ".join(str(v) for v in h.get_all("List-Unsubscribe") or []))
    post = " ".join(str(v) for v in h.get_all("List-Unsubscribe-Post") or [])
    return {"https": [u for u in links if u.lower().startswith("https://")],
            "mailto": [u for u in links if u.lower().startswith("mailto:")],
            "one_click": "list-unsubscribe=one-click" in post.lower().replace(" ", "")}


def public_https(url: str) -> bool:
    """https, and every address its host resolves to is on the public internet."""
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname:
        return False
    try:
        return ipaddress.ip_address(u.hostname).is_global   # a bare address: no lookup needed
    except ValueError:
        pass
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        return False
    return bool(addrs) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None   # a 3xx is the answer; never follow it somewhere else


def one_click(url: str, opener=None) -> int:
    if not public_https(url):
        raise UnsubError(400, "the sender's unsubscribe link isn't a public https address")
    req = urllib.request.Request(url, data=b"List-Unsubscribe=One-Click", method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "User-Agent": "mail-triage unsubscribe"})
    opener = opener or urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return e.code     # accepted, with a page to show; nothing more to do
        raise UnsubError(502, f"the sender refused it (HTTP {e.code})") from None
    except (urllib.error.URLError, OSError) as e:
        raise UnsubError(502, f"couldn't reach the sender: {e}") from None


def by_email(spec: dict, mailto: str, send=None) -> str:
    """Send the unsubscribe email the mailto: link describes, from the account it came to."""
    u = urlparse(mailto)
    to = unquote(u.path)
    if not SENDER.fullmatch(to):
        raise UnsubError(400, "the unsubscribe address isn't an email address")
    q = {k.lower(): v[0] for k, v in parse_qs(u.query).items()}
    msg = EmailMessage()
    msg["From"], msg["To"] = spec["user"], to
    msg["Subject"] = re.sub(r"[\r\n]", " ", q.get("subject") or "unsubscribe")[:200]
    msg.set_content((q.get("body") or "unsubscribe")[:2000])
    if send:
        send(msg)
        return to
    host = spec.get("smtp_host") or spec["host"].replace("imap.", "smtp.", 1)
    with smtplib.SMTP_SSL(host, spec.get("smtp_port", 465), timeout=30) as s:
        s.login(spec["user"], os.environ.get(spec["password_env"], ""))
        s.send_message(msg)
    return to
