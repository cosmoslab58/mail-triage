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
    POST /unsubscribe {"account", "sender"}
                                   {"ok", "method": "one-click"|"email"|"link", "detail"[, "url"]};
                                   see unsubscribe.py
    POST /seen {"account", "msgids": [...], "seen": true|false[, "where": "inbox"|"later"|"spam"]}
                                   mark read or unread, wherever the messages are (`where` first)
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
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from imapclient.imapclient import ALL, JUNK, SENT

import unsubscribe as unsub

# The running triage module, handed over by start(). triage.py runs as __main__, so
# `import triage` here would load a second copy with an empty config.
triage = None

log = logging.getLogger("actions")
DESTS = ("inbox", "later", "spam")
TIER = {"inbox": "today", "later": "later", "spam": "spam"}
JUNK_NAMES = ("Junk", "Spam", "[Gmail]/Spam", "Junk E-mail", "Junk Email")
HEADERS = b"BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]"
HEADERS_TO = b"BODY[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]"
SEEN = b"\\Seen"
PER_FOLDER = 100   # newest messages listed per account and folder


# Logins are kept a few minutes and reused: a fresh login (Gmail most of all) was most of the
# time a button took. One connection per account, used by one request at a time.
KEEP_S = 240
_pool: dict = {}            # account -> (IMAPClient, when last used)
_locks: dict = {}
_locks_guard = threading.Lock()


def _lock(user):
    with _locks_guard:
        return _locks.setdefault(user, threading.Lock())


def _close(c):
    try:
        c.logout()
    except Exception:
        pass


@contextmanager
def imap(spec, connect=None):
    """A logged-in IMAP connection to `spec`'s account. With `connect` (tests) it is a fresh
    one, logged out after. Otherwise a kept one is reused if it still answers, and kept again
    unless something went wrong with it."""
    if connect:
        c = connect()
        try:
            yield c
        finally:
            _close(c)
        return
    user = spec["user"]
    with _lock(user):
        c, hit = None, _pool.pop(user, None)
        if hit and time.monotonic() - hit[1] < KEEP_S:
            try:
                hit[0].noop()
                c = hit[0]
            except Exception:
                _close(hit[0])
        elif hit:
            _close(hit[0])
        c = c or triage.Account(spec).connect()
        keep = False
        try:
            yield c
            keep = True
        except ActionError:
            keep = True     # an answer like 404/410, not a broken connection
            raise
        finally:
            if keep:
                _pool[user] = (c, time.monotonic())
            else:
                _close(c)


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


def sent_folder(c):
    try:
        return c.find_special_folder(SENT)
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
    with imap(spec, connect) as c:
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
    with imap(spec, connect) as c:
        folders = ["INBOX", triage.CFG["later_folder"], all_mail(c), junk_folder(c), sent_folder(c)]
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
    with imap(spec, connect) as c:
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


SEARCH_PER_FOLDER = 20


def search_terms(query):
    """Up to five plain words; nothing that could break out of an IMAP string."""
    words = [w[:40] for w in re.findall(r"[\w@.'-]+", query or "") if len(w) > 1][:5]
    if not words:
        raise ActionError(400, "give some words to search for")
    return words


def search(spec, words, since, before=None, oldest=False, connect=None):
    """One account's mail matching every word (anywhere in the message) between two dates, the
    newest (or with `oldest`, the oldest) per folder. Gmail: All Mail (inbox, archive and sent
    in one); elsewhere INBOX, Later and Sent. Read-only."""
    out = []
    with imap(spec, connect) as c:
        folders = [all_mail(c)]
        if not folders[0]:
            folders = ["INBOX", triage.CFG["later_folder"], sent_folder(c)]
        for f in folders:
            if not f or not c.folder_exists(f):
                continue
            c.select_folder(f, readonly=True)
            crit = ["SINCE", since] + (["BEFORE", before] if before else [])
            for w in words:
                crit += ["TEXT", w]
            found = sorted(c.search(crit, charset="UTF-8"))
            uids = found[:SEARCH_PER_FOLDER] if oldest else found[-SEARCH_PER_FOLDER:]
            if not uids:
                continue
            for data in c.fetch(uids, ["BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)]"]).values():
                h = message_from_bytes(data[HEADERS_TO], policy=policy.default)
                name_, addr = parseaddr(str(h.get("From", "")))
                try:
                    when = parsedate_to_datetime(str(h.get("Date"))).astimezone(triage.TZ).isoformat()
                except Exception:
                    when = ""
                msgid = (triage.ids_in(str(h.get("Message-ID", ""))) or [""])[0]
                if msgid:
                    out.append({"account": spec["user"], "msgid": msgid, "folder": f, "date": when,
                                "sender": addr.lower(), "sender_name": name_ or addr,
                                "to": str(h.get("To", ""))[:200], "subject": str(h.get("Subject", ""))})
    return out


def search_all(query, since, before=None, oldest=False):
    """Every account at once; an account that fails is reported, not fatal."""
    words = search_terms(query)
    accounts = triage.CFG["accounts"]
    with ThreadPoolExecutor(max_workers=len(accounts) or 1) as pool:
        futures = {pool.submit(search, a, words, since, before, oldest): a["user"] for a in accounts}
    items, errors = [], {}
    for f, user in futures.items():
        try:
            items += f.result()
        except Exception as e:
            errors[user] = f"{type(e).__name__}: {e}"
    seen, unique = set(), []
    for m in sorted(items, key=lambda m: m["date"], reverse=not oldest):
        if (m["account"], m["msgid"]) not in seen:   # the same message in two folders
            seen.add((m["account"], m["msgid"]))
            unique.append(m)
    return {"items": unique[:40], "errors": errors}


def set_seen(account, msgids, seen, where=None, connect=None):
    """Mark read or unread. `where` ("inbox", "later", "spam"), when the caller knows it, is
    searched first; the search stops once every message is found (a Gmail message in the
    inbox is the same message in All Mail, so its flag changes there too)."""
    spec = spec_for(account)
    left = [check_msgid(m) for m in msgids]
    if not left:
        return {"ok": True, "changed": 0}
    with imap(spec, connect) as c:
        def folders():
            if where in DESTS:
                yield folder_for(c, where)
            yield from ("INBOX", triage.CFG["later_folder"])
            yield junk_folder(c)
            yield all_mail(c)
        changed, tried = 0, set()
        for f in folders():
            if not left:
                break
            if not f or f in tried:
                continue
            tried.add(f)
            if f != "INBOX" and not c.folder_exists(f):
                continue
            c.select_folder(f)
            uids, found = set(), set()
            for msgid in left:
                hits = c.search(["HEADER", "Message-ID", msgid])
                if hits:
                    uids.update(hits)
                    found.add(msgid)
            if uids:
                (c.add_flags if seen else c.remove_flags)(sorted(uids), [SEEN])
                changed += len(uids)
            left = [m for m in left if m not in found]
        log.info("%s %d message(s) in %s", "read" if seen else "unread", changed, account)
        return {"ok": True, "changed": changed}


def unsubscribe(account, sender, connect=None, post=None, send=None):
    """Unsubscribe `account` from `sender`'s mailings, by the newest message it has from them."""
    spec = spec_for(account)
    try:
        sender = unsub.check_sender(sender)
    except unsub.UnsubError as e:
        raise ActionError(e.status, str(e)) from None
    if triage.q("SELECT 1 FROM messages WHERE account=? AND sender=? AND phishing=1 LIMIT 1", account, sender):
        raise ActionError(403, "that sender sends phishing; unsubscribing would only confirm your address. Mark it spam.")
    since = triage.now().date() - dt.timedelta(days=120)
    newest = None   # (date, raw headers)
    with imap(spec, connect) as c:
        for f in (triage.CFG["later_folder"], "INBOX"):
            if f != "INBOX" and not c.folder_exists(f):
                continue
            c.select_folder(f, readonly=True)
            uids = c.search(["FROM", sender, "SINCE", since])
            if not uids:
                continue
            uid = max(uids)
            got = c.fetch([uid], ["INTERNALDATE", "BODY.PEEK[HEADER.FIELDS (LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST DATE)]"])[uid]
            when = got.get(b"INTERNALDATE")
            if newest is None or (when and newest[0] and when > newest[0]):
                newest = (when, got[unsub.HEADERS])
    if newest is None:
        raise ActionError(404, "no mail from them in the last four months to unsubscribe with")
    opts = unsub.options(newest[1])
    try:
        if opts["one_click"] and opts["https"]:
            unsub.one_click(opts["https"][0], post)
            method, detail, out = "one-click", opts["https"][0], {}
        elif opts["mailto"]:
            to = unsub.by_email(spec, opts["mailto"][0], send)
            method, detail, out = "email", to, {}
        elif opts["https"]:
            method, detail, out = "link", opts["https"][0], {"url": opts["https"][0]}
        else:
            raise ActionError(404, "their mail has no unsubscribe link; mark it spam instead")
    except unsub.UnsubError as e:
        raise ActionError(e.status, str(e)) from None
    triage.q("INSERT OR REPLACE INTO unsubscribed (account, sender, ts, method, detail) VALUES (?,?,?,?,?)",
             account, sender, triage.now().isoformat(), method, detail[:500])
    log.info("unsubscribe %s from %s: %s", account, sender, method)
    return {"ok": True, "method": method, "detail": detail, **out}


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
        if url.path == "/search":
            # after/before (YYYY-MM-DD) or days back; oldest=1 lists the earliest matches first
            try:
                today = triage.now().date()
                after = qs.get("after", [""])[0]
                since = dt.date.fromisoformat(after) if after else \
                    today - dt.timedelta(days=min(max(int(qs.get("days", ["365"])[0]), 1), 3650))
                before = qs.get("before", [""])[0]
                before = dt.date.fromisoformat(before) if before else None
            except ValueError:
                return self._send(400, {"error": "days must be a number, after/before YYYY-MM-DD"})
            oldest = qs.get("oldest", [""])[0] == "1"
            return self._handle(lambda: search_all(qs.get("q", [""])[0], since, before, oldest))
        if url.path == "/message":
            account, msgid = qs.get("account", [""])[0], qs.get("msgid", [""])[0]
            if not (account and msgid):
                return self._send(400, {"error": "need account and msgid"})
            return self._handle(lambda: message(account, msgid, read=qs.get("read", [""])[0] == "1"))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/move", "/seen", "/unsubscribe"):
            return self._send(404, {"error": "not found"})

        def run():
            try:
                size = int(self.headers.get("Content-Length", 0))
                if size > 1_000_000:
                    raise ActionError(413, "request too large")
                body = json.loads(self.rfile.read(size) or b"{}")
            except ValueError:
                raise ActionError(400, "body must be JSON")
            if path == "/unsubscribe":
                return unsubscribe(str(body.get("account", "")), body.get("sender"))
            if path == "/seen":
                if not body.get("account") or not isinstance(body.get("msgids"), list) or "seen" not in body:
                    raise ActionError(400, "need account, msgids and seen")
                return set_seen(body["account"], [str(m) for m in body["msgids"]][:500], bool(body["seen"]),
                                where=body.get("where"))
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
