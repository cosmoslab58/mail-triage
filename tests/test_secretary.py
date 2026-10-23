import time

import pytest

import secretary

RAW = (b"From: Dr Lee's office <frontdesk@clinic.example>\r\nTo: a@x.com\r\nSubject: Appointment confirmed\r\n"
       b"Message-ID: <appt@clinic.example>\r\nDate: Mon, 19 Oct 2026 09:00:00 +0000\r\n\r\nSee you Tuesday.")
SPEC = {"user": "a@x.com", "host": "imap.gmail.com", "password_env": "P"}


class FakeDAV:
    """A dict of href -> ics text, speaking just enough of CalDAV for secretary._http."""

    def __init__(self):
        self.store = {}

    def __call__(self, method, url, body=None, headers=None):
        if method == "PUT":
            if (headers or {}).get("If-None-Match") == "*" and url in self.store:
                return 412, "", None
            self.store[url] = body
            return 201, "", '"e"'
        if method == "GET":
            return (200, self.store[url], '"e"') if url in self.store else (404, "", None)
        if method == "DELETE":
            return (200, "", None) if self.store.pop(url, None) else (404, "", None)
        raise AssertionError(method)


@pytest.fixture
def sec(env, monkeypatch):
    triage, llm, notify = env
    secretary.setup({"todo_url": "https://dav/x/todo/", "calendar_url": "https://dav/x/calendar/"}, triage)
    dav = FakeDAV()
    monkeypatch.setattr(secretary, "_http", dav)
    llm.reply.update(todo="", due="", events=[], reply_closes=False)
    yield triage, llm, notify, dav
    secretary.setup(None, triage)


def classify_and_record(triage, llm, tier, raw=RAW, **reply):
    llm.reply.update(tier=tier, **reply)
    m = triage.describe(raw)
    out = triage.classify("a@x.com", m, known=False, reply_to_me=False)
    triage.q("""INSERT OR IGNORE INTO messages (account,msgid,ts,sender,sender_name,subject,tier,summary)
                VALUES (?,?,?,?,?,?,?,?)""", "a@x.com", m["msgid"], triage.now().isoformat(), m["sender"],
             m["sender_name"], m["subject"], tier, out["summary"])
    secretary.record(SPEC, m, out, tier)
    return m


def todos(dav):
    return {k: v for k, v in dav.store.items() if "/todo/" in k}


def test_schema_only_grows_when_caldav_is_configured(env):
    triage, _, _ = env
    secretary.setup(None, triage)
    assert "todo" not in triage.schema()["properties"]
    secretary.setup({"todo_url": "u"}, triage)
    try:
        s = triage.schema()
        assert {"todo", "due", "events"} <= set(s["required"]) and "DO" in triage.instructions()
    finally:
        secretary.setup(None, triage)


def test_now_mail_with_an_action_becomes_a_top_priority_todo(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "now", todo="Call the clinic back", due="2026-12-01")
    secretary.push()
    (ics,) = todos(dav).values()
    assert "SUMMARY:Call the clinic back" in ics and "DUE;VALUE=DATE:20261201" in ics
    assert "PRIORITY:1" in ics and "STATUS:NEEDS-ACTION" in ics and "rfc822msgid" in ics


def test_information_only_and_later_mail_make_no_todo(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", todo="")
    classify_and_record(triage, llm, "later", todo="Buy the sale shoes")
    secretary.push()
    assert not todos(dav)


def test_events_are_created_once_and_never_in_the_past(sec):
    triage, llm, _, dav = sec
    ev = {"title": "Dentist with Dr Lee", "start": "2099-03-04T14:30", "end": "", "location": "12 Main St"}
    old = {"title": "Old thing", "start": "2001-01-01", "end": "", "location": ""}
    classify_and_record(triage, llm, "later", events=[ev, old])
    classify_and_record(triage, llm, "today", events=[{**ev, "title": "Reminder: Dr Lee dentist"}])
    secretary.push()
    events = [v for k, v in dav.store.items() if "/calendar/" in k]
    assert len(events) == 1
    assert "DTSTART:20990304T143000Z" in events[0] and "DTEND:20990304T153000Z" in events[0]
    assert "LOCATION:12 Main St" in events[0]


def test_phishing_produces_nothing(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "now", phishing=True, todo="Verify your account",
                        events=[{"title": "x", "start": "2099-01-01", "end": "", "location": ""}])
    secretary.push()
    assert not dav.store


def test_ticking_off_in_the_app_marks_the_mail_read(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", todo="Sign the form")
    secretary.push()
    (href, ics), = todos(dav).items()
    dav.store[href] = ics.replace("STATUS:NEEDS-ACTION", "STATUS:COMPLETED")
    secretary.poll()

    class C:
        flagged = []
        def search(self, crit): return [42]
        def add_flags(self, uids, flags): self.flagged.append((uids, flags))
    c = C()
    secretary.mark_read("a@x.com", True, c)
    assert c.flagged == [([42], [b"\\Seen"])]
    assert triage.q("SELECT state FROM dav")[0][0] == "seen"


def test_read_only_boxes_are_never_flagged(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", todo="Reply to the customer")
    secretary.push()
    dav.store.clear()   # deleted in the app counts as done too
    secretary.poll()

    class C:
        def search(self, crit): raise AssertionError("must not touch a move: false mailbox")
    secretary.mark_read("a@x.com", False, C())
    assert triage.q("SELECT state FROM dav")[0][0] == "seen"


def test_mail_moved_to_later_closes_its_todo_on_the_server(sec):
    triage, llm, _, dav = sec
    m = classify_and_record(triage, llm, "today", todo="Pay the invoice")
    secretary.push()
    triage.q("UPDATE messages SET corrected='later' WHERE msgid=?", m["msgid"])
    secretary.push()
    (ics,) = todos(dav).values()
    assert secretary.is_completed(ics) and "SUMMARY:Pay the invoice" in ics
    assert triage.q("SELECT state FROM dav")[0][0] == "closed"


def test_reading_the_mail_does_not_close_the_todo(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", todo="Pay the invoice")
    secretary.push()
    secretary.poll()
    assert triage.q("SELECT state FROM dav")[0][0] == "open"


def test_digest_counts_open_todos(sec):
    triage, llm, notify, _ = sec
    classify_and_record(triage, llm, "today", todo="Pay the invoice")
    triage.daily_digest()
    assert "1 open to-do" in notify.sent[-1][1]


def test_long_lines_fold_without_splitting_characters():
    folded = secretary._fold("SUMMARY:" + "é" * 80)
    assert all(len(x.encode()) <= 75 for x in folded.split("\r\n"))
    assert secretary._unfold(folded)[0] == "SUMMARY:" + "é" * 80


def mail(n, subject="Hey", in_reply_to="", sender="Mike <mike@example.com>"):
    irt = f"In-Reply-To: {in_reply_to}\r\nReferences: {in_reply_to}\r\n" if in_reply_to else ""
    return (f"From: {sender}\r\nTo: a@x.com\r\nSubject: {subject}\r\nMessage-ID: <m{n}@ex>\r\n{irt}"
            "\r\nhello").encode()


def ev(change, title, start, location=""):
    return [{"change": change, "title": title, "start": start, "end": "", "location": location}]


class Imap:
    """Just enough IMAP for check_replies and mark_read."""
    def __init__(self, sent_refs=()):
        self.sent_refs, self.flagged, self.selected = list(sent_refs), [], None
    def find_special_folder(self, f): return "Sent"
    def select_folder(self, f, readonly=False): self.selected = f
    def search(self, crit): return [1] if crit[0] == "SINCE" else [hash(crit[-1]) % 1000]
    def fetch(self, uids, parts):
        hdr = "".join(f"In-Reply-To: {r}\r\n" for r in self.sent_refs).encode()
        return {1: {b"BODY[HEADER.FIELDS (IN-REPLY-TO REFERENCES)]": hdr}}
    def add_flags(self, uids, flags): self.flagged += uids


def test_one_conversation_is_one_todo(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1), todo="Reply to Mike (said hi)")
    secretary.push()
    classify_and_record(triage, llm, "today", mail(2, "Re: Hey", "<m1@ex>"), todo="Reply to Mike (beer Tue or Thu)")
    secretary.push()
    (ics,) = todos(dav).values()
    assert "SUMMARY:Reply to Mike (beer Tue or Thu)" in ics
    assert triage.q("SELECT msgids FROM dav")[0][0] == "<m1@ex> <m2@ex>"


def test_thanks_in_the_thread_adds_no_todo_but_is_marked_read_with_it(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1), todo="Reply to Mike")
    classify_and_record(triage, llm, "today", mail(2, "Re: Hey", "<m1@ex>"), todo="")
    secretary.push()
    dav.store.clear()   # ticked off (deleted) in the app
    secretary.poll()
    c = Imap()
    secretary.mark_read("a@x.com", True, c)
    assert len(c.flagged) == 2


def test_replying_closes_a_reply_todo(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1), todo="Reply to Mike", reply_closes=True)
    secretary.push()
    secretary.check_replies("a@x.com", Imap(sent_refs=["<other@ex>"]))
    assert triage.q("SELECT state FROM dav")[0][0] == "open"
    secretary.check_replies("a@x.com", Imap(sent_refs=["<m1@ex>"]))
    secretary.push()
    (ics,) = todos(dav).values()
    assert secretary.is_completed(ics) and triage.q("SELECT state FROM dav")[0][0] == "closed"


def test_replying_does_not_close_a_todo_that_needs_more(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1), todo="Pay the invoice", reply_closes=False)
    secretary.push()
    secretary.check_replies("a@x.com", Imap(sent_refs=["<m1@ex>"]))
    assert triage.q("SELECT state FROM dav")[0][0] == "open"


def test_a_moved_appointment_moves_the_event(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1, "Booked"), events=ev("new", "Dentist with Dr Lee", "2099-03-04T14:30"))
    secretary.push()
    classify_and_record(triage, llm, "today", mail(2, "Rescheduled"),
                        events=ev("update", "Dentist with Dr Lee", "2099-03-05T09:00"))
    secretary.push()
    (ics,) = [v for k, v in dav.store.items() if "/calendar/" in k]
    assert "DTSTART:20990305T090000Z" in ics and "LOCATION" not in ics


def test_a_cancelled_appointment_is_deleted(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1, "Booked"), events=ev("new", "Dentist with Dr Lee", "2099-03-04T14:30"))
    secretary.push()
    classify_and_record(triage, llm, "today", mail(2, "Re: Booked", "<m1@ex>"),
                        events=ev("cancel", "Dentist appointment", "2099-03-04T14:30"))
    secretary.push()
    assert not [k for k in dav.store if "/calendar/" in k]
    assert triage.q("SELECT state FROM dav")[0][0] == "cancelled"


def test_an_unknown_change_notice_becomes_a_new_event_and_a_stray_cancel_does_nothing(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1, "Moved"), events=ev("update", "Soccer practice", "2099-04-01T17:00"))
    classify_and_record(triage, llm, "today", mail(2, "Off"), events=ev("cancel", "Piano lesson", "2099-04-02T17:00"))
    secretary.push()
    assert len([k for k in dav.store if "/calendar/" in k]) == 1


def test_reminder_only_when_the_email_gives_a_deadline(sec):
    triage, llm, _, dav = sec
    classify_and_record(triage, llm, "today", mail(1), todo="Pay it", due="2099-01-05")
    classify_and_record(triage, llm, "today", mail(2, "Other"), todo="Look at it", due="")
    secretary.push()
    by_title = {("Pay it" in v): v for v in todos(dav).values()}
    assert "TRIGGER;RELATED=END:PT9H" in by_title[True] and "VALARM" not in by_title[False]


def test_deadman_goes_down_after_an_hour_of_caldav_failures(sec, monkeypatch):
    triage, llm, _, _ = sec
    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(secretary, "_http", boom)
    monkeypatch.setattr(triage, "STARTED", time.time() - 7200)
    monkeypatch.setitem(triage.LAST_OK, "a@x.com", time.time())
    classify_and_record(triage, llm, "today", todo="Pay it")
    secretary.sync_once(0)
    assert triage.deadman_status()[0] == "up"            # failing, but not for an hour yet
    secretary.FAILING["since"] -= 3601
    status, msg = triage.deadman_status()
    assert status == "down" and "caldav" in msg and "refused" in msg
    monkeypatch.setattr(secretary, "_http", FakeDAV())
    secretary.sync_once(0)
    assert triage.deadman_status()[0] == "up"


def test_urgent_push_opens_the_message(sec, monkeypatch):
    triage, _, notify, _ = sec
    monkeypatch.setitem(triage.CFG, "accounts", [SPEC, {"user": "b@x.com", "host": "imap.other"}])
    monkeypatch.setitem(triage.CFG, "notify", {"click_url": "https://todo.example"})
    triage.push_now("a@x.com", {"sender_name": "Jo", "subject": "s", "msgid": "<m1@ex>"}, {"summary": "x", "reason": "r"})
    triage.push_now("b@x.com", {"sender_name": "Jo", "subject": "s", "msgid": "<m1@ex>"}, {"summary": "x", "reason": "r"})
    assert "rfc822msgid" in notify.urls[0] and notify.urls[1] == "https://todo.example"
