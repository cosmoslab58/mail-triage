"""Optional CalDAV output: mail becomes to-dos and calendar events. Off unless `caldav:` is set.

    caldav:
      todo_url: https://dav.example.com/alex/todo/           # a VTODO collection
      calendar_url: https://dav.example.com/alex/calendar/   # a VEVENT collection (optional)
      user_env: CALDAV_USER
      password_env: CALDAV_PASSWORD

The classifier also answers "is there something to do?" and "is there a date to keep?":
  - a now/today email that asks for action becomes a to-do (a "now" one at top priority),
    due on the deadline the email states, or today;
  - an appointment, booking or meeting in any non-phishing email becomes a calendar event.

Any CalDAV app (Tasks.org, DAVx5, Thunderbird, Apple Reminders) shows and ticks off the to-dos.
Ticking one off, or deleting it, marks its email read. Moving the email to Later or deleting it
closes the to-do. Reading the email does NOT: read-and-forgotten is exactly what this is for.
Mailboxes with `move: false` are never touched; their to-dos just close.
"""
from __future__ import annotations

import base64
import datetime as dt
import logging
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import quote

triage = None   # the running triage module, handed over by start() (see actions.py)
log = logging.getLogger("secretary")
CFG = None
POLL = 300      # seconds between checks of open to-dos

# State of a to-do row:
#   new      recorded, not yet on the server
#   open     on the server, waiting for you
#   closing  its email left the inbox: mark it completed on the server
#   closed   finished because of the email (nothing left to do)
#   done     you ticked it off or deleted it: mark the email read
#   seen     finished because of you, email marked read
# An event row is new, then sent.
SCHEMA = """
CREATE TABLE IF NOT EXISTS dav (
  uid TEXT PRIMARY KEY, account TEXT, msgid TEXT, kind TEXT, title TEXT, due TEXT,
  start TEXT, end_ TEXT, location TEXT, note TEXT, link TEXT, priority INTEGER,
  state TEXT, created TEXT, updated TEXT);
CREATE INDEX IF NOT EXISTS dav_msg ON dav (account, msgid);
"""


def enabled():
    return CFG is not None


def setup(cfg, triage_module):
    """Called from triage.init(): remember the config and create the table."""
    global CFG, triage
    triage = triage_module
    CFG = cfg or None
    if CFG:
        with triage._lock:
            triage._db.executescript(SCHEMA)


# ---------------------------------------------------------------- classifier fields

def schema_fields(owner):
    return {
        "todo": {"type": "string", "description":
                 f"If this email asks {owner} to do something (pay, reply, sign, book, bring, decide), "
                 "that action as a short imperative under 70 characters, e.g. 'Pay Comcast bill ($82)'. "
                 "Empty string if it is information only."},
        "due": {"type": "string", "description":
                "YYYY-MM-DD deadline for that action if the email states or clearly implies one; else empty"},
        "events": {"type": "array", "description":
                   f"Appointments, reservations, flights, meetings, school or club events {owner} is booked "
                   "for or clearly expected at, with a date in the email. Not sales or marketing events, "
                   "not deadlines (those go in due). Usually empty.",
                   "items": {"type": "object", "additionalProperties": False,
                             "required": ["title", "start", "end", "location"],
                             "properties": {
                                 "title": {"type": "string", "description": "under 60 characters"},
                                 "start": {"type": "string", "description":
                                           "local time YYYY-MM-DDTHH:MM, or YYYY-MM-DD if all day"},
                                 "end": {"type": "string", "description": "same format, or empty"},
                                 "location": {"type": "string", "description": "address or place, or empty"}}}},
    }


INSTRUCTIONS = """
Separately, note what {owner} must DO (todo, due) and any dates to KEEP (events). Resolve
relative dates ("next Tuesday") against the email's Date header. A newsletter or sale is never
a todo or an event."""


# ---------------------------------------------------------------- recording

def link_for(spec, msgid):
    """A link that opens the message, where the webmail can search by Message-ID."""
    if spec.get("host") == "imap.gmail.com":
        return (f"https://mail.google.com/mail/u/{spec['user']}/#search/"
                + quote("rfc822msgid:" + msgid.strip("<>"), safe=""))
    return ""


def record(spec, m, out, tier):
    """Queue the to-do and events this email produced. Never talks to the network."""
    if not enabled() or out.get("phishing"):
        return
    account, stamp = spec["user"], triage.now().isoformat()
    note = f"{m['sender_name']}: {m['subject']}\n{out.get('summary', '')}\n({account})"
    link = link_for(spec, m["msgid"])
    rows = []
    todo = (out.get("todo") or "").strip()
    if tier in ("now", "today") and todo and CFG.get("todo_url"):
        rows.append(("todo", todo[:120], _date(out.get("due")) or triage.now().date().isoformat(),
                     "", "", "", 1 if tier == "now" else 5))
    if CFG.get("calendar_url"):
        for ev in out.get("events") or []:
            start, end = _when(ev.get("start")), _when(ev.get("end"))
            if not start or not ev.get("title") or _past(start) or duplicate_event(ev["title"], start):
                continue
            rows.append(("event", ev["title"][:120], "", start, end or "", (ev.get("location") or "")[:200], 0))
    for kind, title, due, start, end, location, priority in rows:
        triage.q("""INSERT INTO dav (uid,account,msgid,kind,title,due,start,end_,location,note,link,priority,
                    state,created,updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?)""",
                 f"{uuid.uuid4()}@mail-triage", account, m["msgid"], kind, title, due, start, end,
                 location, note, link, priority, stamp, stamp)
        log.info("queued %s for %s: %s", kind, account, title)


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
    for (other,) in triage.q("SELECT title FROM dav WHERE kind='event' AND start=?", start):
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


def href(row):
    base = CFG["todo_url"] if row["kind"] == "todo" else CFG["calendar_url"]
    return base.rstrip("/") + "/" + quote(row["uid"].split("@")[0], safe="") + ".ics"


def rows(where, *args):
    cols = ("uid", "account", "msgid", "kind", "title", "due", "start", "end_", "location", "note",
            "link", "priority", "state")
    return [dict(zip(cols, r, strict=True)) for r in triage.q(f"SELECT {', '.join(cols)} FROM dav WHERE {where}", *args)]


def set_state(uid, state):
    triage.q("UPDATE dav SET state=?, updated=? WHERE uid=?", state, triage.now().isoformat(), uid)


def close_left_mail():
    """To-dos whose email was moved to Later, marked spam, or deleted/archived elsewhere."""
    for uid, state in triage.q("""SELECT d.uid, d.state FROM dav d JOIN messages m
                                  ON m.account=d.account AND m.msgid=d.msgid
                                  WHERE d.kind='todo' AND d.state IN ('new','open')
                                  AND (m.gone_at IS NOT NULL OR m.corrected IN ('later','spam'))"""):
        set_state(uid, "closed" if state == "new" else "closing")


def push():
    """Send new rows and closures. Cheap: touches only rows that changed. One bad row is
    logged and retried next round; it never holds up the others."""
    close_left_mail()
    for row in rows("state IN ('new','closing')"):
        try:
            if row["state"] == "new":
                # 412 = already there (sent just before a restart): that's fine too
                _http("PUT", href(row), ics(row), {"If-None-Match": "*"})
                set_state(row["uid"], "open" if row["kind"] == "todo" else "sent")
                continue
            status, text, etag = _http("GET", href(row))
            if status == 200 and not is_completed(text):
                status, _, _ = _http("PUT", href(row), completed(text), {"If-Match": etag} if etag else {})
                if status == 412:
                    continue   # edited in the app meanwhile: try again next round
            set_state(row["uid"], "closed")
        except Exception as e:
            log.error("caldav %s %r failed: %s: %s", row["kind"], row["title"], type(e).__name__, e)


def poll():
    """Which open to-dos did you tick off (or delete) in your app?"""
    for row in rows("kind='todo' AND state='open'"):
        status, text, _ = _http("GET", href(row))
        if status in (404, 410) or (status == 200 and is_completed(text)):
            set_state(row["uid"], "done")
            log.info("to-do done: %s", row["title"])


def loop():
    last_poll = 0
    while True:
        try:
            push()
            if time.time() - last_poll > POLL:
                poll()
                last_poll = time.time()
        except Exception as e:
            log.error("caldav sync failed: %s: %s", type(e).__name__, e)
        time.sleep(60)


def mark_read(account, move, c):
    """In the account's IMAP thread (INBOX selected): \\Seen for to-dos you finished."""
    if not enabled():
        return
    for uid, msgid in triage.q("SELECT uid, msgid FROM dav WHERE account=? AND state='done'", account):
        if move:
            found = c.search(["HEADER", "Message-ID", msgid])
            if found:
                c.add_flags(found, [b"\\Seen"])
        set_state(uid, "seen")


def open_todos():
    return triage.q("SELECT COUNT(*), MIN(created) FROM dav WHERE kind='todo' AND state IN ('new','open')")[0]


def start():
    if not enabled():
        return
    threading.Thread(target=loop, name="caldav", daemon=True).start()
    log.info("caldav: to-dos -> %s, events -> %s", CFG.get("todo_url") or "-", CFG.get("calendar_url") or "-")
