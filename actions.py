"""Optional HTTP API for a front end: move a message between Inbox, Later and Spam, and list
what is sitting in each account's spam folder. Off unless `actions:` is configured.

    actions:
      listen: 0.0.0.0:8941              # publish it on loopback or a private network only
      token_env: TRIAGE_ACTIONS_TOKEN   # every request needs "Authorization: Bearer <token>"

    GET  /accounts                 [{"user", "move"}]
    GET  /spam?days=30             [{"account", "msgid", "sender", "sender_name", "subject", "date"}]
    GET  /folder?name=inbox|later&days=14
                                   {"items": [{"account", "msgid", "sender", "sender_name", "subject",
                                    "date", "seen"}], "errors": {account: message}}, newest first
    GET  /message?account=&msgid=[&read=1]
                                   {"account", "msgid", "folder", "from", "to", "cc", "date", "subject",
                                    "text", "link", "seen"}; peeked, unless read=1 marks it read
    POST /seen {"account", "msgids": [...], "seen": true|false}
                                   mark read or unread, wherever the messages are
    POST /move {"account", "msgid", "to": "inbox"|"later"|"spam"}
                                   410 if the message has left all three; it is marked gone

A move is recorded as a correction (`corrected` = the tier it moved to), the same signal as
moving the message by hand, so the classifier learns from it. A message rescued from spam is
recorded before it lands in the inbox, so the watcher does not sort it all over again.
Accounts with `move: false` (boxes another system, like a helpdesk, also reads) are never
filed to Later, here or by the sorter; but the owner may mark them read or unread and move
mail to Spam or back to the inbox. Helpdesks such as EspoCRM fetch by UID, not by the read
flag, so neither hides mail from them.
"""
from __future__ import annotations

import datetime as dt
import hmac
import html
import json
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from imapclient.imapclient import ALL, JUNK

# The running triage module, handed over by start(). triage.py runs as __main__, so
# `import triage` here would load a second copy with an empty config.
triage = None

log = logging.getLogger("actions")
DESTS = ("inbox", "later", "spam")
TIER = {"inbox": "today", "later": "later", "spam": "spam"}
JUNK_NAMES = ("Junk", "Spam", "[Gmail]/Spam", "Junk E-mail", "Junk Email")
HEADERS = b"BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]"
SEEN = b"\\Seen"
PER_FOLDER = 100   # newest messages listed per account and folder


class ActionError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def spec_for(account):
    spec = next((a for a in triage.CFG["accounts"] if a["user"] == account), None)
    if not spec:
        raise ActionError(404, f"unknown account {account}")
    return spec


def junk_folder(c):
    found = c.find_special_folder(JUNK)
    if found:
        return found
    return next((n for n in JUNK_NAMES if c.folder_exists(n)), None)


def folder_for(c, dest):
    if dest == "inbox":
        return "INBOX"
    if dest == "later":
        return triage.CFG["later_folder"]
    return junk_folder(c)


# A Message-ID as the parser keeps it: <...> of printable ASCII, no spaces or brackets inside.
# Anything else is refused before it reaches an IMAP command: a CR/LF in a search string
# would end the command and start another, and an empty one would match every message.
MSGID = re.compile(r"<[\x21-\x3b\x3d\x3f-\x7e]{1,900}>")


def check_msgid(msgid):
    if not isinstance(msgid, str) or not MSGID.fullmatch(msgid):
        raise ActionError(400, "not a Message-ID")
    return msgid


def all_mail(c):
    """Gmail's All Mail (any language), where archived mail lives; None elsewhere."""
    try:
        return c.find_special_folder(ALL)
    except Exception:
        return None


def locate(c, msgid, folders):
    check_msgid(msgid)
    for f in folders:
        if f and c.folder_exists(f):
            c.select_folder(f)
            uids = c.search(["HEADER", "Message-ID", msgid])
            if uids:
                return f, uids
    return None, []


def headers(c, uid):
    raw = c.fetch([uid], ["BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]"])[uid][HEADERS]
    h = message_from_bytes(raw, policy=policy.default)
    name, addr = parseaddr(str(h.get("From", "")))
    return {"sender": addr.lower(), "sender_name": name or addr, "subject": str(h.get("Subject", "")),
            "msgid": str(h.get("Message-ID", "")).strip(), "date": str(h.get("Date", ""))}


def record(account, msgid, dest, found_in, c, uid):
    """Write the correction before the move, so a message landing in INBOX is already known."""
    row = triage.q("SELECT tier FROM messages WHERE account=? AND msgid=?", account, msgid)
    tier = TIER[dest]
    if row:
        triage.q("UPDATE messages SET corrected=? WHERE account=? AND msgid=?",
                 None if row[0][0] == tier else tier, account, msgid)
        return
    # Never classified (the provider filed it as spam before we saw it): add it as spam,
    # corrected to where it went.
    h = headers(c, uid)
    triage.q("""INSERT OR IGNORE INTO messages (account,msgid,ts,sender,sender_name,subject,tier,category,
                summary,reason,phishing,bulk,notified,applied,digested,corrected)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
             account, msgid, triage.now().isoformat(), h["sender"], h["sender_name"], h["subject"],
             "spam" if found_in != "INBOX" else "today", "spam", h["subject"][:90],
             f"moved by hand from {found_in}", 0, 0, None, 1, 1, tier)


def move(account, msgid, dest, connect=None):
    if dest not in DESTS:
        raise ActionError(400, f"'to' must be one of {', '.join(DESTS)}")
    check_msgid(msgid)
    spec = spec_for(account)
    if not spec.get("move", True) and dest == "later":
        raise ActionError(403, f"{account} is never filed to Later (move: false)")
    c = (connect or triage.Account(spec).connect)()
    try:
        target = folder_for(c, dest)
        if not target:
            raise ActionError(409, f"{account} has no spam folder")
        others = [f for f in ("INBOX", triage.CFG["later_folder"], junk_folder(c)) if f and f != target]
        found_in, uids = locate(c, msgid, others)
        if not uids:
            if locate(c, msgid, [target])[1]:
                return {"ok": True, "moved_from": None, "note": f"already in {target}"}
            triage.q("UPDATE messages SET gone_at=? WHERE account=? AND msgid=?",
                     triage.now().isoformat(), account, msgid)
            raise ActionError(410, "no longer in Inbox, Later or Spam (deleted or archived in your mail app)")
        record(account, msgid, dest, found_in, c, uids[0])
        c.select_folder(found_in)
        c.move(uids, target)
        log.info("moved %s %s: %s -> %s", account, msgid, found_in, target)
        return {"ok": True, "moved_from": found_in, "moved_to": target}
    finally:
        try:
            c.logout()
        except Exception:
            pass


def readable(msg, limit=100_000):
    """The message as plain text with its line breaks: the text part, else the HTML flattened."""
    plain = htm = None
    # a forwarded message's own parts are not this message's body
    nested = {id(p) for part in msg.walk() if part.get_content_type() == "message/rfc822"
              for p in part.walk() if p is not part}
    for part in msg.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename() or id(part) in nested:
            continue
        try:
            payload = part.get_content()
        except Exception:
            continue
        if not isinstance(payload, str):
            continue
        if part.get_content_type() == "text/plain" and not (plain or "").strip():
            plain = payload
        elif part.get_content_type() == "text/html" and htm is None:
            htm = payload
    if not (plain or "").strip() and htm:
        htm = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", htm)
        htm = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h[1-6]|table)>", "\n", htm)
        plain = html.unescape(re.sub(r"<[^>]+>", " ", htm))
    text = re.sub(r"[ \t\xa0]+", " ", (plain or "").replace("\r\n", "\n"))
    text = re.sub(r"\n[ ]+", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()[:limit]


def message(account, msgid, read=False, connect=None):
    """One message by Message-ID, peeked so it stays unread unless `read` (and the account
    allows it)."""
    check_msgid(msgid)
    spec = spec_for(account)
    c = (connect or triage.Account(spec).connect)()
    try:
        folders = ["INBOX", triage.CFG["later_folder"], all_mail(c), junk_folder(c)]
        found_in, uids = locate(c, msgid, folders)
        if not uids:
            raise ActionError(410, "no longer in Inbox, Later or Spam (deleted or archived in your mail app)")
        c.select_folder(found_in, readonly=True)
        got = c.fetch([uids[0]], ["FLAGS", "BODY.PEEK[]"])[uids[0]]
        raw, seen = got[b"BODY[]"], SEEN in (got.get(b"FLAGS") or ())
        if read and not seen:
            c.select_folder(found_in)
            c.add_flags([uids[0]], [SEEN])
            seen = True
    finally:
        try:
            c.logout()
        except Exception:
            pass
    msg = message_from_bytes(raw, policy=policy.default)
    try:
        when = parsedate_to_datetime(str(msg.get("Date"))).astimezone(triage.TZ).isoformat()
    except Exception:
        when = ""
    return {"account": account, "msgid": msgid, "folder": found_in,
            "from": str(msg.get("From", "")), "to": str(msg.get("To", "")), "cc": str(msg.get("Cc", "")),
            "date": when, "subject": str(msg.get("Subject", "")), "text": readable(msg),
            "link": triage.secretary.link_for(spec, msgid), "seen": seen}


def listing(spec, folder, days, connect=None):
    """The newest messages of one account's folder ("inbox", "later" or "spam") with their
    read state. Read-only: listing never marks anything read."""
    c = (connect or triage.Account(spec).connect)()
    try:
        name = folder_for(c, folder)
        if not name or not c.folder_exists(name):
            return []
        c.select_folder(name, readonly=True)
        uids = sorted(c.search(["SINCE", triage.now().date() - dt.timedelta(days=days)]))[-PER_FOLDER:]
        out = []
        if uids:
            for data in c.fetch(uids, ["FLAGS", "BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]"]).values():
                h = message_from_bytes(data[HEADERS], policy=policy.default)
                name_, addr = parseaddr(str(h.get("From", "")))
                try:
                    when = parsedate_to_datetime(str(h.get("Date"))).astimezone(triage.TZ).isoformat()
                except Exception:
                    when = ""
                out.append({"account": spec["user"],
                            "msgid": (triage.ids_in(str(h.get("Message-ID", ""))) or [""])[0],
                            "sender": addr.lower(), "sender_name": name_ or addr,
                            "subject": str(h.get("Subject", "")), "date": when,
                            "seen": SEEN in (data.get(b"FLAGS") or ())})
        return [m for m in out if m["msgid"]]
    finally:
        try:
            c.logout()
        except Exception:
            pass


def spam_for(spec, days, connect=None):
    return listing(spec, "spam", days, connect)


def list_folder(folder, days=30):
    """Every account's folder at once; an account that fails is reported, not fatal."""
    accounts = triage.CFG["accounts"]
    with ThreadPoolExecutor(max_workers=len(accounts) or 1) as pool:
        futures = {pool.submit(listing, a, folder, days): a["user"] for a in accounts}
    items, errors = [], {}
    for f, user in futures.items():
        try:
            items += f.result()
        except Exception as e:
            errors[user] = f"{type(e).__name__}: {e}"
    items.sort(key=lambda m: m["date"], reverse=True)
    return {"items": items, "errors": errors}


def list_spam(days=30):
    return list_folder("spam", days)


def set_seen(account, msgids, seen, connect=None):
    spec = spec_for(account)
    msgids = [check_msgid(m) for m in msgids]
    if not msgids:
        return {"ok": True, "changed": 0}
    c = (connect or triage.Account(spec).connect)()
    try:
        folders = ["INBOX", triage.CFG["later_folder"], junk_folder(c), all_mail(c)]
        changed = 0
        for f in folders:
            if not (f and c.folder_exists(f)):
                continue
            c.select_folder(f)
            uids = set()
            for msgid in msgids:
                uids.update(c.search(["HEADER", "Message-ID", msgid]))
            if uids:
                (c.add_flags if seen else c.remove_flags)(sorted(uids), [SEEN])
                changed += len(uids)
        log.info("%s %d message(s) in %s", "read" if seen else "unread", changed, account)
        return {"ok": True, "changed": changed}
    finally:
        try:
            c.logout()
        except Exception:
            pass


def days(qs, default):
    """?days= as 1-90; anything else is a 400, not a dropped connection."""
    try:
        return min(max(int(qs.get("days", [default])[0]), 1), 90)
    except ValueError:
        raise ActionError(400, "days must be a number") from None


class Handler(BaseHTTPRequestHandler):
    token = ""

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        return bool(self.token) and hmac.compare_digest(got.encode(), self.token.encode())

    def _handle(self, fn):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            return self._send(200, fn())
        except ActionError as e:
            return self._send(e.status, {"error": str(e)})
        except Exception as e:
            log.exception("action failed")
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/accounts":
            return self._handle(lambda: [{"user": a["user"], "move": a.get("move", True)}
                                         for a in triage.CFG["accounts"]])
        qs = parse_qs(url.query)
        if url.path == "/spam":
            return self._handle(lambda: list_spam(days(qs, 30)))
        if url.path == "/folder":
            name = qs.get("name", [""])[0]
            if name not in DESTS:
                return self._send(400, {"error": f"name must be one of {', '.join(DESTS)}"})
            return self._handle(lambda: list_folder(name, days(qs, 14)))
        if url.path == "/message":
            account, msgid = qs.get("account", [""])[0], qs.get("msgid", [""])[0]
            if not (account and msgid):
                return self._send(400, {"error": "need account and msgid"})
            return self._handle(lambda: message(account, msgid, read=qs.get("read", [""])[0] == "1"))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/move", "/seen"):
            return self._send(404, {"error": "not found"})

        def run():
            try:
                size = int(self.headers.get("Content-Length", 0))
                if size > 1_000_000:
                    raise ActionError(413, "request too large")
                body = json.loads(self.rfile.read(size) or b"{}")
            except ValueError:
                raise ActionError(400, "body must be JSON")
            if path == "/seen":
                if not body.get("account") or not isinstance(body.get("msgids"), list) or "seen" not in body:
                    raise ActionError(400, "need account, msgids and seen")
                return set_seen(body["account"], [str(m) for m in body["msgids"]][:500], bool(body["seen"]))
            if not all(body.get(k) for k in ("account", "msgid", "to")):
                raise ActionError(400, "need account, msgid and to")
            return move(body["account"], body["msgid"], body["to"])
        return self._handle(run)


def start(cfg, triage_module):
    """Start the API in a daemon thread if configured; returns the server or None."""
    global triage
    triage = triage_module
    if not cfg:
        return None
    token = os.environ.get(cfg.get("token_env", "TRIAGE_ACTIONS_TOKEN"), "")
    if not token:
        log.error("actions configured but %s is empty; not starting the API", cfg.get("token_env"))
        return None
    host, _, port = cfg.get("listen", "127.0.0.1:8941").rpartition(":")
    Handler.token = token
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    threading.Thread(target=server.serve_forever, name="actions", daemon=True).start()
    log.info("actions API listening on %s:%s", host, port)
    return server
