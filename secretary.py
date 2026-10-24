"""Optional CalDAV output: mail becomes to-dos and calendar events. Off unless `caldav:` is set.

    caldav:
      todo_url: https://dav.example.com/alex/todo/           # a VTODO collection
      calendar_url: https://dav.example.com/alex/calendar/   # a VEVENT collection (optional)
      contacts_url: https://dav.example.com/alex/contacts/   # a CardDAV address book (optional, read only)
      user_env: CALDAV_USER
      password_env: CALDAV_PASSWORD

The classifier also answers "is there something to do?" and "is there a date to keep?":
  - a now/today email that asks for action becomes a to-do (a "now" one at top priority),
    due on the deadline the email states (with a 9:00 reminder that day), or today;
  - an appointment, booking or meeting in any non-phishing email becomes a calendar event;
    a later email that moves or cancels it updates or deletes that event.

One conversation is one to-do: a new message in a thread with an open to-do updates it.
Any CalDAV app (Tasks.org, DAVx5, Thunderbird, Apple Reminders) shows and ticks off the to-dos.
Ticking one off, or deleting it, marks its emails read. Replying closes a to-do that only
needed a reply. Moving the email to Later or deleting it closes the to-do. Reading the email
does NOT: read-and-forgotten is exactly what this is for.
Mailboxes with `move: false` are never touched; their to-dos just close.
"""
from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from email import message_from_bytes
from urllib.parse import quote

from imapclient.imapclient import SENT

triage = None   # the running triage module, handed over by setup() (see actions.py)
log = logging.getLogger("secretary")
CFG = None
POLL = 300      # seconds between checks of open to-dos and of Sent folders
FAILING = {"since": None, "error": ""}   # dead-man input: CalDAV failing since when, and why

# State of a to-do row:
#   new      recorded, not yet on the server
#   open     on the server, waiting for you
#   dirty    on the server, but a newer message in its thread changed it: PUT again
#   closing  its email left the inbox, or you replied: mark it completed on the server
#   closed   finished without you ticking it (nothing left to do)
#   done     you ticked it off or deleted it: mark its emails read
#   seen     finished because of you, emails marked read
# An event row is new -> sent; dirty -> sent when it moved; cancel -> cancelled when called off.
OPEN = ("new", "open", "dirty")
SCHEMA = """
CREATE TABLE IF NOT EXISTS dav (
  uid TEXT PRIMARY KEY, account TEXT, msgid TEXT, kind TEXT, title TEXT, due TEXT,
  start TEXT, end_ TEXT, location TEXT, note TEXT, link TEXT, priority INTEGER,
  state TEXT, created TEXT, updated TEXT);
CREATE INDEX IF NOT EXISTS dav_msg ON dav (account, msgid);
"""
# Added 2026-10-23: every message of the conversation, the sender, and two to-do flags.
COLUMNS = {"msgids": "TEXT", "sender": "TEXT", "reply_closes": "INTEGER DEFAULT 0", "remind": "INTEGER DEFAULT 0"}


def enabled():
    return CFG is not None


def setup(cfg, triage_module):
    """Called from triage.init(): remember the config and create the table."""
    global CFG, triage
    triage = triage_module
    CFG = cfg or None
    FAILING.update(since=None, error="")
    if CFG:
        with triage._lock:
            triage._db.executescript(SCHEMA)
            have = {r[1] for r in triage._db.execute("PRAGMA table_info(dav)")}
            for name, kind in COLUMNS.items():
                if name not in have:
                    triage._db.execute(f"ALTER TABLE dav ADD COLUMN {name} {kind}")
            triage._db.execute("UPDATE dav SET msgids=msgid WHERE msgids IS NULL")


# ---------------------------------------------------------------- classifier fields

def schema_fields(owner):
    return {
        "todo": {"type": "string", "description":
                 f"If this email asks {owner} to do something (pay, reply, sign, book, bring, decide), "
                 "that action as a short imperative under 70 characters, e.g. 'Pay Comcast bill ($82)'. "
                 "Empty string if it is information only."},
        "due": {"type": "string", "description":
                "YYYY-MM-DD deadline for that action if the email states or clearly implies one; else empty"},
        "reply_closes": {"type": "boolean", "description":
                         f"true if {owner} replying to this email is all the todo needs (answer a question, "
                         "accept an invitation, write back to a friend); false if something else must happen "
                         "(pay, sign, book, send a file) or there is no todo"},
        "events": {"type": "array", "description":
                   f"Appointments, reservations, flights, meetings, school or club events {owner} is booked "
                   "for or clearly expected at, with a date in the email. Not sales or marketing events, "
                   "not deadlines (those go in due). Usually empty.",
                   "items": {"type": "object", "additionalProperties": False,
                             "required": ["change", "title", "start", "end", "location"],
                             "properties": {
                                 "change": {"type": "string", "enum": ["new", "update", "cancel"],
                                            "description": "new booking; update = an existing one moved or "
                                                           "changed (give the NEW details); cancel = called off"},
                                 "title": {"type": "string", "description": "under 60 characters"},
                                 "start": {"type": "string", "description":
                                           "local time YYYY-MM-DDTHH:MM, or YYYY-MM-DD if all day"},
                                 "end": {"type": "string", "description": "same format, or empty"},
                                 "location": {"type": "string", "description": "address or place, or empty"}}}},
    }


INSTRUCTIONS = """
Separately, note what {owner} must DO (todo, due, reply_closes) and any dates to KEEP (events).
Resolve relative dates ("next Tuesday") against the email's Date header. A newsletter or sale is
never a todo or an event."""


# ---------------------------------------------------------------- recording

def link_for(spec, msgid):
    """A link that opens the message, where the webmail can search by Message-ID."""
    if spec.get("host") == "imap.gmail.com" and msgid:
        return (f"https://mail.google.com/mail/u/{spec['user']}/#search/"
                + quote("rfc822msgid:" + msgid.strip("<>"), safe=""))
    return ""


def record(spec, m, out, tier):
    """Queue the to-do and events this email produced. Never talks to the network."""
    if not enabled() or out.get("phishing"):
        return
    account = spec["user"]
    refs = set(m.get("refs") or [])
    note = f"{m['sender_name']}: {m['subject']}\n{out.get('summary', '')}\n({account})"
    link = link_for(spec, m["msgid"])
    todo = (out.get("todo") or "").strip()
    thread = in_thread(account, "todo", refs)
    if tier in ("now", "today") and todo and CFG.get("todo_url"):
        due = _date(out.get("due"))
        fields = {"title": todo[:120], "note": note, "link": link, "msgid": m["msgid"],
                  "reply_closes": int(bool(out.get("reply_closes"))), "remind": int(bool(due))}
        if thread:
            prev = thread[0]
            fields.update(due=due or prev["due"], priority=min(prev["priority"], 1 if tier == "now" else 5),
                          msgids=f"{prev['msgids']} {m['msgid']}", remind=int(bool(due) or prev["remind"]))
            update(prev, fields)
            log.info("updated to-do for %s: %s", account, todo)
        else:
            insert("todo", account, m, fields, due=due or triage.now().date().isoformat(),
                   priority=1 if tier == "now" else 5)
    elif thread:
        # e.g. "thanks!" in the same conversation: no new task, but ticking off marks it read too
        triage.q("UPDATE dav SET msgids=? WHERE uid=?", f"{thread[0]['msgids']} {m['msgid']}", thread[0]["uid"])
    if CFG.get("calendar_url"):
        for ev in out.get("events") or []:
            record_event(account, m, refs, ev, note, link)


def record_event(account, m, refs, ev, note, link):
    start, end = _when(ev.get("start")), _when(ev.get("end"))
    title = (ev.get("title") or "").strip()[:120]
    change = ev.get("change") or "new"
    if change in ("update", "cancel"):
        target = find_event(account, m["sender"], refs, title)
        if target and change == "cancel":
            set_state(target["uid"], "cancel" if target["state"] in ("sent", "dirty") else "cancelled")
            log.info("cancelling event: %s", target["title"])
            return
        if target and start and not _past(start):
            update(target, {"title": title or target["title"], "start": start, "end_": end or "",
                            "location": (ev.get("location") or target["location"])[:200], "note": note,
                            "link": link, "msgid": m["msgid"], "msgids": f"{target['msgids']} {m['msgid']}"})
            log.info("moved event: %s -> %s", target["title"], start)
            return
        if change == "cancel":
            return
    if not start or not title or _past(start) or duplicate_event(title, start):
        return
    insert("event", account, m, {"title": title, "note": note, "link": link, "msgid": m["msgid"]},
           start=start, end_=end or "", location=(ev.get("location") or "")[:200])


def insert(kind, account, m, fields, **more):
    row = {"uid": f"{uuid.uuid4()}@mail-triage", "account": account, "kind": kind, "due": "", "start": "",
           "end_": "", "location": "", "priority": 0, "msgids": m["msgid"], "sender": m["sender"],
           "reply_closes": 0, "remind": 0, "state": "new", "created": triage.now().isoformat(),
           "updated": triage.now().isoformat(), **fields, **more}
    triage.q(f"INSERT INTO dav ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})", *row.values())
    log.info("queued %s for %s: %s", kind, account, row["title"])


def update(row, fields):
    """Change a queued or sent item; it is re-sent whole on the next round."""
    state = "new" if row["state"] == "new" else "dirty"
    sets = ", ".join(f"{k}=?" for k in fields)
    triage.q(f"UPDATE dav SET {sets}, state=?, updated=? WHERE uid=?",
             *fields.values(), state, triage.now().isoformat(), row["uid"])


def in_thread(account, kind, refs):
    """Open items whose conversation this message belongs to (it quotes one of their Message-IDs)."""
    if not refs:
        return []
    return [r for r in rows(f"account=? AND kind=? AND state IN {OPEN}", account, kind)
            if refs & set((r["msgids"] or r["msgid"]).split())]


def _words(s):
    return {w for w in s.lower().replace(":", " ").split() if len(w) > 2}


def find_event(account, sender, refs, title):
    """The event a change notice is about: same conversation, else same sender with a similar title,
    else any upcoming event with a clearly similar title."""
    live = [r for r in rows("kind='event' AND state IN ('new','sent','dirty') AND start>=?",
                            triage.now().date().isoformat())]
    by_thread = [r for r in live if r["account"] == account and refs & set((r["msgids"] or "").split())]
    if by_thread:
        return by_thread[-1]
    words = _words(title)

    def similar(r, share):
        theirs = _words(r["title"])
        return bool(words & theirs) and len(words & theirs) >= share * min(len(words), len(theirs))
    return next((r for r in reversed(live) if r["sender"] == sender and similar(r, 0.34)), None) \
        or next((r for r in reversed(live) if similar(r, 0.6)), None)


def _date(s):
    try:
        return dt.date.fromisoformat((s or "").strip()[:10]).isoformat()
    except ValueError:
        return ""


def _when(s):
    """'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM' (local), normalised; '' if unusable."""
    s = (s or "").strip()
    try:
        if len(s) == 10:
            return dt.date.fromisoformat(s).isoformat()
        return dt.datetime.fromisoformat(s[:16]).strftime("%Y-%m-%dT%H:%M")
    except ValueError:
        return ""


def _past(start):
    return start[:10] < triage.now().date().isoformat()


def duplicate_event(title, start):
    """The same booking tends to arrive three times: confirmation, reminder, change notice."""
    words = set(title.lower().split())
    for (other,) in triage.q("SELECT title FROM dav WHERE kind='event' AND start=? AND state!='cancelled'", start):
        theirs = set(other.lower().split())
        if words & theirs and len(words & theirs) * 2 >= min(len(words), len(theirs)):
            return True
    return False


# ---------------------------------------------------------------- iCalendar

def _esc(s):
    return (s or "").replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _fold(line):
    out, b = [], line.encode()
    while len(b) > 75:
        cut = 75
        while cut and (b[cut] & 0xC0) == 0x80:   # never split a UTF-8 character
            cut -= 1
        out.append(b[:cut].decode())
        b = b" " + b[cut:]
    out.append(b.decode())
    return "\r\n".join(out)


def _utc(t=None):
    return (t or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _stamp(local):
    """iCalendar property suffix for a local date or datetime: ';VALUE=DATE:20261025' or ':...Z'."""
    if len(local) == 10:
        return ";VALUE=DATE:" + local.replace("-", "")
    return ":" + _utc(dt.datetime.fromisoformat(local).replace(tzinfo=triage.TZ))


def ics(row):
    comp = "VTODO" if row["kind"] == "todo" else "VEVENT"
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//mail-triage//EN", f"BEGIN:{comp}",
             f"UID:{row['uid']}", f"DTSTAMP:{_utc()}", f"SUMMARY:{_esc(row['title'])}",
             f"DESCRIPTION:{_esc(row['note'])}"]
    if row["link"]:
        lines.append(f"URL:{row['link']}")
    if comp == "VTODO":
        lines += [f"DUE{_stamp(row['due'])}", "STATUS:NEEDS-ACTION", f"PRIORITY:{row['priority']}"]
        if row.get("remind"):
            # 9:00 on the day the email says it's due (DUE is that day's midnight)
            lines += ["BEGIN:VALARM", "ACTION:DISPLAY", f"DESCRIPTION:{_esc(row['title'])}",
                      "TRIGGER;RELATED=END:PT9H", "END:VALARM"]
    else:
        start = row["start"]
        if len(start) == 10:
            end = row["end_"] if len(row["end_"] or "") == 10 and row["end_"] > start else None
            end = end or (dt.date.fromisoformat(start) + dt.timedelta(days=1)).isoformat()
        else:
            end = row["end_"] if len(row["end_"] or "") == 16 and row["end_"] > start else None
            end = end or (dt.datetime.fromisoformat(start) + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M")
        lines += [f"DTSTART{_stamp(start)}", f"DTEND{_stamp(end)}"]
        if row["location"]:
            lines.append(f"LOCATION:{_esc(row['location'])}")
    lines += [f"END:{comp}", "END:VCALENDAR"]
    return "\r\n".join(_fold(x) for x in lines) + "\r\n"


def _unfold(text):
    return text.replace("\r\n ", "").replace("\r\n\t", "").replace("\n ", "").splitlines()


def is_completed(text):
    for line in _unfold(text):
        name = line.split(":", 1)[0].split(";", 1)[0].upper()
        if (name == "STATUS" and line.upper().endswith(":COMPLETED")) or name == "COMPLETED" \
                or (name == "PERCENT-COMPLETE" and line.endswith(":100")):
            return True
    return False


def completed(text):
    """The same to-do, marked completed. Keeps whatever else the app changed (title, notes)."""
    out = []
    for line in _unfold(text):
        name = line.split(":", 1)[0].split(";", 1)[0].upper()
        if name in ("STATUS", "COMPLETED", "PERCENT-COMPLETE"):
            continue
        if line.upper() == "END:VTODO":
            out += ["STATUS:COMPLETED", f"COMPLETED:{_utc()}", "PERCENT-COMPLETE:100"]
        out.append(line)
    return "\r\n".join(_fold(x) for x in out) + "\r\n"


# ---------------------------------------------------------------- CalDAV

def _http(method, url, body=None, headers=None):
    """(status, text, etag). 404 and 412 come back as statuses, everything else raises."""
    user = os.environ.get(CFG.get("user_env", "CALDAV_USER"), "")
    pw = os.environ.get(CFG.get("password_env", "CALDAV_PASSWORD"), "")
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    h = {"Authorization": f"Basic {auth}", **(headers or {})}
    if body is not None:
        h["Content-Type"] = "text/calendar; charset=utf-8"
    req = urllib.request.Request(url, body.encode() if body is not None else None, h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode(errors="replace"), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code in (404, 410, 412):
            return e.code, "", None
        raise


def contact_emails():
    """Email addresses in the address book at `contacts_url` (optional), lowercased. The sorter
    counts them as known people, the same as addresses the owner has written to."""
    url = (CFG or {}).get("contacts_url")
    if not url:
        return set()
    status, text, _ = _http("GET", url)
    if status != 200:
        raise RuntimeError(f"address book {url}: HTTP {status}")
    text = re.sub(r"\r?\n[ \t]", "", text)   # unfold
    found = re.findall(r"^(?:[\w-]+\.)?EMAIL[^:\n]*:(.+?)\r?$", text, re.M | re.I)
    return {e.strip().lower() for e in found if "@" in e}


def href(row):
    base = CFG["todo_url"] if row["kind"] == "todo" else CFG["calendar_url"]
    return base.rstrip("/") + "/" + quote(row["uid"].split("@")[0], safe="") + ".ics"


COLS = ("uid", "account", "msgid", "kind", "title", "due", "start", "end_", "location", "note", "link",
        "priority", "state", "msgids", "sender", "reply_closes", "remind", "created", "updated")


def rows(where, *args):
    return [dict(zip(COLS, r, strict=True))
            for r in triage.q(f"SELECT {', '.join(COLS)} FROM dav WHERE {where} ORDER BY created", *args)]


def set_state(uid, state, seen=None):
    """With `seen` (the row's `updated` when it was read), only if nothing changed it since:
    an email can update the row on its account's thread while a sync is mid-request."""
    if seen is None:
        triage.q("UPDATE dav SET state=?, updated=? WHERE uid=?", state, triage.now().isoformat(), uid)
    else:
        triage.q("UPDATE dav SET state=?, updated=? WHERE uid=? AND updated=?",
                 state, triage.now().isoformat(), uid, seen)


def _ok(status, what):
    if status not in (200, 201, 204):
        raise RuntimeError(f"{what}: HTTP {status}")


def collection_there(url):
    """The collection answers. A to-do's 404 means it was deleted only if its list still exists;
    a renamed or missing list must not turn every to-do into "done" (and its mail into read)."""
    status, _, _ = _http("PROPFIND", url, None, {"Depth": "0"})
    return status == 207


def close_left_mail():
    """To-dos whose newest email was moved to Later, marked spam, or deleted/archived elsewhere."""
    for uid, state in triage.q(f"""SELECT d.uid, d.state FROM dav d JOIN messages m
                                   ON m.account=d.account AND m.msgid=d.msgid
                                   WHERE d.kind='todo' AND d.state IN {OPEN}
                                   AND (m.gone_at IS NOT NULL OR m.corrected IN ('later','spam'))"""):
        set_state(uid, "closed" if state == "new" else "closing")


def push():
    """Send what changed. One bad row is logged and retried next round; it never holds up the
    others. Returns the last error, or '' when everything went through."""
    close_left_mail()
    error = ""
    for row in rows("state IN ('new','dirty','closing','cancel')"):
        try:
            sent = "open" if row["kind"] == "todo" else "sent"
            if row["state"] == "new":
                # 412 = already there (sent just before a restart): that's fine too
                status, _, _ = _http("PUT", href(row), ics(row), {"If-None-Match": "*"})
                if status != 412:
                    _ok(status, "PUT")
                set_state(row["uid"], sent, row["updated"])
            elif row["state"] == "dirty":
                # Look first: a to-do ticked off in the app since must stay done, not be
                # reopened by this email's update, and edits made there are not overwritten.
                status, text, etag = _http("GET", href(row))
                if row["kind"] == "todo" and status == 200 and is_completed(text):
                    set_state(row["uid"], "done", row["updated"])
                    continue
                headers = {"If-Match": etag} if status == 200 and etag else {}
                status, _, _ = _http("PUT", href(row), ics(row), headers)
                if status == 412:
                    continue   # changed in the app between our GET and PUT: next round
                _ok(status, "PUT")
                set_state(row["uid"], sent, row["updated"])
            elif row["state"] == "cancel":
                status, _, _ = _http("DELETE", href(row))
                if status not in (404, 410):
                    _ok(status, "DELETE")
                set_state(row["uid"], "cancelled", row["updated"])
            else:
                status, text, etag = _http("GET", href(row))
                if status == 200 and not is_completed(text):
                    status, _, _ = _http("PUT", href(row), completed(text), {"If-Match": etag} if etag else {})
                    if status == 412:
                        continue   # edited in the app meanwhile: try again next round
                    _ok(status, "PUT")
                set_state(row["uid"], "closed", row["updated"])
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
            log.error("caldav %s %r failed: %s", row["kind"], row["title"], error)
    return error


def poll():
    """Which open to-dos did you tick off (or delete) in your app?"""
    there = None   # asked once, and only if some to-do is missing
    for row in rows("kind='todo' AND state='open'"):
        status, text, _ = _http("GET", href(row))
        gone = status in (404, 410)
        if gone and there is None:
            there = collection_there(CFG["todo_url"])
            if not there:
                log.error("caldav: the to-do list %s is not answering; nothing marked done", CFG["todo_url"])
        if (gone and there) or (status == 200 and is_completed(text)):
            set_state(row["uid"], "done", row["updated"])
            log.info("to-do done: %s", row["title"])


def sync_once(last_poll):
    """One round: push, and poll when due. Updates FAILING; returns when it last polled."""
    error = ""
    try:
        error = push()
        if time.time() - last_poll > POLL:
            poll()
            last_poll = time.time()
    except Exception as e:
        error = f"{type(e).__name__}: {e}"
        log.error("caldav sync failed: %s", error)
    if error:
        FAILING["since"] = FAILING["since"] or time.time()
        FAILING["error"] = error[:120]
    else:
        FAILING.update(since=None, error="")
    return last_poll


def loop():
    last_poll = 0
    while True:
        last_poll = sync_once(last_poll)
        time.sleep(60)


def health():
    """'' when fine, else why the to-do list has been out of sync for over an hour."""
    if FAILING["since"] and time.time() - FAILING["since"] > 3600:
        return f"caldav failing {int((time.time() - FAILING['since']) // 60)} min: {FAILING['error']}"
    return ""


# ---------------------------------------------------------------- IMAP side (account threads)

def mark_read(account, move, c):
    """INBOX selected: \\Seen for every email of the to-dos you finished."""
    if not enabled():
        return
    for row in rows("account=? AND state='done'", account):
        if move:
            for msgid in set((row["msgids"] or row["msgid"]).split()):
                found = c.search(["HEADER", "Message-ID", msgid])
                if found:
                    c.add_flags(found, [b"\\Seen"])
        set_state(row["uid"], "seen")


def check_replies(account, c):
    """Close to-dos that only needed a reply, once a reply is in the account's Sent folder.
    Leaves some other folder selected: the caller re-selects INBOX."""
    if not enabled():
        return
    waiting = rows(f"account=? AND kind='todo' AND reply_closes=1 AND state IN {OPEN}", account)
    if not waiting:
        return
    sent = c.find_special_folder(SENT)
    if not sent:
        return
    c.select_folder(sent, readonly=True)
    uids = c.search(["SINCE", dt.date.fromisoformat(waiting[0]["created"][:10])])
    quoted = set()
    for i in range(0, len(uids), 500):
        for data in c.fetch(uids[i:i + 500], ["BODY.PEEK[HEADER.FIELDS (IN-REPLY-TO REFERENCES)]"]).values():
            h = message_from_bytes(data[b"BODY[HEADER.FIELDS (IN-REPLY-TO REFERENCES)]"])
            quoted |= set(triage.ids_in(str(h.get("In-Reply-To", ""))) + triage.ids_in(str(h.get("References", ""))))
    for row in waiting:
        if quoted & set((row["msgids"] or row["msgid"]).split()):
            set_state(row["uid"], "closed" if row["state"] == "new" else "closing")
            log.info("replied, closing to-do: %s", row["title"])


def open_todos():
    return triage.q(f"SELECT COUNT(*), MIN(created) FROM dav WHERE kind='todo' AND state IN {OPEN}")[0]


def start():
    if not enabled():
        return
    threading.Thread(target=loop, name="caldav", daemon=True).start()
    log.info("caldav: to-dos -> %s, events -> %s", CFG.get("todo_url") or "-", CFG.get("calendar_url") or "-")
