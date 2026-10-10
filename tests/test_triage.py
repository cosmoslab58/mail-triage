import datetime as dt
import time

import notifiers

RAW = (b"From: Jo Bloggs <jo@example.com>\r\nTo: a@x.com\r\nSubject: Invoice due Friday\r\n"
       b"Message-ID: <m1@example.com>\r\nIn-Reply-To: <sent1@x.com>\r\n"
       b"Content-Type: text/html\r\n\r\n<p>Please&nbsp;pay</p><script>evil()</script>")


def test_describe_parses_headers_and_strips_html(env):
    triage, _, _ = env
    m = triage.describe(RAW)
    assert m["sender"] == "jo@example.com" and m["sender_name"] == "Jo Bloggs"
    assert m["msgid"] == "<m1@example.com>" and m["refs"] == ["<sent1@x.com>"]
    assert m["body"] == "Please pay" and not m["bulk"]


def test_bulk_detection(env):
    triage, _, _ = env
    assert triage.describe(b"From: a@b.c\r\nList-Unsubscribe: <mailto:x>\r\n\r\nhi")["bulk"]


def test_quiet_hours_across_midnight(env):
    triage, _, _ = env
    at = lambda h, m: dt.datetime(2026, 1, 1, h, m, tzinfo=triage.TZ)  # noqa: E731
    assert triage.in_quiet_hours(at(23, 0)) and triage.in_quiet_hours(at(6, 59))
    assert not triage.in_quiet_hours(at(7, 0)) and not triage.in_quiet_hours(at(12, 0))


def test_prompt_carries_owner_profile_and_untrusted_email(env):
    triage, llm, _ = env
    triage.classify("a@x.com", triage.describe(RAW), known=False, reply_to_me=False)
    system, user, schema = llm.calls[0]
    assert "Alex" in system and "Bills matter." in system
    assert "<email>" in user and "untrusted" in system
    assert schema["properties"]["tier"]["enum"] == ["now", "today", "later"]


def test_known_correspondent_is_never_filed_away(env):
    triage, llm, _ = env
    llm.reply["tier"] = "later"
    out = triage.classify("a@x.com", triage.describe(RAW), known=True, reply_to_me=False)
    assert out["tier"] == "today" and out["reason"].startswith("floor")


def test_correction_lifts_the_floor_for_that_sender(env):
    triage, llm, _ = env
    triage.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier,corrected) VALUES (?,?,?,?,?,?,?)",
             "a@x.com", "<old>", "2026-01-01", "jo@example.com", "promo", "today", "later")
    llm.reply["tier"] = "later"
    assert triage.classify("a@x.com", triage.describe(RAW), known=True, reply_to_me=False)["tier"] == "later"


def test_phishing_is_never_pushed(env):
    triage, llm, _ = env
    llm.reply.update(tier="now", phishing=True)
    assert triage.classify("a@x.com", triage.describe(RAW), known=False, reply_to_me=False)["tier"] == "later"


def test_bad_tier_from_model_raises_so_mail_fails_open(env):
    triage, llm, _ = env
    llm.reply["tier"] = "urgent!!"
    try:
        triage.classify("a@x.com", triage.describe(RAW), known=False, reply_to_me=False)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_failed_message_still_reaches_the_digest(env):
    triage, _, notify = env
    triage.record_failure("a@x.com", 7, RAW, RuntimeError("boom"))
    triage.daily_digest()
    title, body, level = notify.sent[-1]
    assert "1 to look at" in title and "Could not be sorted" in body and level == "normal"


def test_deadman_reports_starting_then_stale_then_ok(env, monkeypatch):
    triage, _, _ = env
    monkeypatch.setattr(triage, "STARTED", time.time())
    assert triage.deadman_status()[1].startswith("starting")
    monkeypatch.setattr(triage, "STARTED", time.time() - 3600)
    assert triage.deadman_status() == ("down", "stale: a@x.com")
    triage.LAST_OK["a@x.com"] = time.time()
    assert triage.deadman_status() == ("up", "1 accounts ok")


def test_notifier_levels_map_to_each_backend(monkeypatch):
    posts = []
    monkeypatch.setattr(notifiers, "_post", lambda url, body, headers, form=False: posts.append(body))
    notifiers.make({"type": "gotify", "url": "http://g"}).send("t", "m", "urgent")
    notifiers.make({"type": "ntfy", "topic": "x"}).send("t", "m", "low")
    notifiers.make({"type": "pushover"}).send("t", "m", "normal")
    assert [p["priority"] for p in posts] == [8, 2, 0]


def test_scan_marks_mail_that_left_inbox_and_later_as_gone(env):
    triage, _, _ = env
    for mid in ("<kept@1>", "<deleted@1>", "<back@1>"):
        triage.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier) VALUES (?,?,?,?,?,?)",
                 "a@x.com", mid, triage.now().isoformat(), "s@x", "s", "today")
    triage.q("UPDATE messages SET gone_at='earlier' WHERE msgid='<back@1>'")
    a = triage.Account({"user": "a@x.com", "host": "h", "password_env": "P"})
    a.mark_gone({"<kept@1>", "<back@1>"}, "2000-01-01")
    got = dict(triage.q("SELECT msgid, gone_at IS NOT NULL FROM messages"))
    assert got == {"<kept@1>": 0, "<deleted@1>": 1, "<back@1>": 0}
