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


def test_no_quiet_hours(env, monkeypatch):
    triage, _, _ = env
    monkeypatch.setitem(triage.CFG, "quiet_hours", [])
    assert not triage.in_quiet_hours()


def test_an_emergency_goes_out_at_the_top_priority(env, monkeypatch):
    triage, _, _ = env
    sent = []
    monkeypatch.setattr(triage.NOTIFY, "send", lambda title, msg, level, url=None: sent.append(level) or True)
    m = {"sender_name": "Mom", "subject": "Dad fell", "msgid": "<1@x>"}
    triage.push_now("a@b.c", m, {"summary": "s", "reason": "r", "emergency": True})
    triage.push_now("a@b.c", m, {"summary": "s", "reason": "r"})
    assert sent == ["emergency", "urgent"]
    assert triage.notifiers.Gotify.PRIORITY["emergency"] == 10


def test_quiet_hours_across_midnight(env, monkeypatch):
    triage, _, _ = env
    monkeypatch.setitem(triage.CFG, "quiet_hours", triage.DEFAULTS["quiet_hours"])
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


def test_digest_level_is_configurable(env, monkeypatch):
    triage, _, notify = env
    monkeypatch.setitem(triage.CFG, "digest_level", "low")
    triage.daily_digest()
    assert notify.sent[-1][2] == "low"


def test_bad_digest_level_is_rejected(env, tmp_path):
    triage = env[0]
    cfg = tmp_path / "config.yaml"
    cfg.write_text("owner: A\ntimezone: UTC\nllm: {provider: gemini, model: x}\n"
                   "accounts: [{user: a}]\ndigest_level: loud\n")
    try:
        triage.load_config(cfg)
    except SystemExit as e:
        assert "digest_level" in str(e)
        return
    raise AssertionError("expected SystemExit")


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
    notifiers.make({"type": "gotify", "url": "http://g"}).send("t", "m", "urgent", url="https://x")
    assert posts[-1]["extras"]["client::notification"] == {"click": {"url": "https://x"}}


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


def test_digests_can_be_switched_off(env, tmp_path):
    triage = env[0]
    cfg = tmp_path / "config.yaml"
    for value in ("off", "null", "none"):
        cfg.write_text(f"owner: A\ntimezone: UTC\nllm: {{provider: gemini, model: x}}\n"
                       f"accounts: [{{user: a}}]\ndigest_time: {value}\n")
        assert triage.load_config(cfg)["digest_time"] is None


def test_an_emergency_is_always_pushed_and_never_phishing(env):
    triage, llm, _ = env
    m = triage.describe(RAW)
    llm.reply.update(tier="today", emergency=True)
    assert triage.classify("a@x.com", m, known=False, reply_to_me=False)["tier"] == "now"
    llm.reply.update(tier="now", emergency=True, phishing=True)
    out = triage.classify("a@x.com", m, known=False, reply_to_me=False)
    assert out["tier"] == "later" and not out["emergency"]
    assert "emergency" in triage.schema()["required"]


def test_mail_from_dispatch_is_filed_not_pushed(env, monkeypatch):
    triage, _, _ = env
    m = triage.describe(b"From: service@x.dev\r\nX-Dispatch: 1\r\nSubject: [Proxmox] disk failing\r\n\r\nbody")
    assert m["dispatched"] and not triage.describe(b"From: a@b.c\r\nSubject: hi\r\n\r\nx")["dispatched"]


LIST_MAIL = (b"From: billing@vendor.com\r\nTo: treasurer@club.org\r\nList-Id: <treasurer.club.org>\r\n"
             b"Message-ID: <inv1@vendor.com>\r\nSubject: Your invoice\r\n\r\nInvoice attached.")


class FolderIMAP:
    def __init__(self):
        self.moves, self.flags, self.made = [], [], []
    def folder_exists(self, f): return f in self.made
    def create_folder(self, f): self.made.append(f)
    def subscribe_folder(self, f): pass
    def move(self, uids, dest): self.moves.append((uids, dest))
    def fetch(self, uids, parts): return {}   # moved: gone from INBOX
    def add_flags(self, uids, flags): self.flags.append((uids, flags))


CLUB = {"Club": {"domains": ["club.org"], "subject": ["CLUB"]}}


def test_topic_mail_is_matched_by_list_id_address_or_subject(env):
    triage = env[0]
    triage.CFG["folders"] = CLUB
    m = triage.describe(LIST_MAIL)
    assert m["list_id"] == "treasurer.club.org" and "club.org" in m["addr_domains"]
    assert triage.topic_folder(m) == "Club"
    assert triage.topic_folder({"list_id": "club.org"}) == "Club"
    assert triage.topic_folder({"addr_domains": ["gmail.com", "mail.club.org"]}) == "Club"
    board = triage.describe(b"From: Piotr <p@gmail.com>\r\nTo: me@gmail.com\r\nCc: Bob <b@yahoo.com>\r\n"
                            b"Subject: Re: [CLUB] Vote requested\r\n\r\nyes")
    assert triage.topic_folder(board) == "Club"
    assert triage.topic_folder({"subject": "Clubhouse news", "addr_domains": ["notclub.org"]}) is None
    assert triage.topic_folder({"list_id": "", "addr_domains": [], "subject": ""}) is None
    assert triage.topic_folder(triage.describe(RAW)) is None
    assert triage.extra_folders() == ["Club"]


def test_list_mail_is_filed_in_its_folder_but_now_stays_in_inbox(env):
    triage, llm, notify = env
    triage.CFG["folders"] = CLUB
    a = triage.Account({"user": "a@x.com", "host": "h", "password_env": "P"})
    for tier, uid in (("later", 1), ("today", 2), ("now", 3)):
        llm.reply.update(tier=tier)
        c = FolderIMAP()
        a.handle(c, uid, LIST_MAIL.replace(b"<inv1@", f"<inv{uid}@".encode()))
        if tier == "now":
            assert c.moves == [] and c.flags == [([3], [b"\\Flagged"])] and notify.sent
        else:
            assert c.moves == [([uid], "Club")]
    llm.reply.update(tier="today")
    c = FolderIMAP()
    a.handle(c, 9, RAW)   # ordinary mail: today stays in INBOX
    assert c.moves == []


def test_a_quiet_topic_never_rings_but_an_emergency_does(env):
    triage, llm, notify = env
    triage.CFG["folders"] = {"Club": {**CLUB["Club"], "quiet": True}}
    a = triage.Account({"user": "a@x.com", "host": "h", "password_env": "P"})
    llm.reply.update(tier="now")
    c = FolderIMAP()
    a.handle(c, 1, LIST_MAIL)
    assert c.moves == [([1], "Club")] and c.flags == [] and not notify.sent
    assert triage.q("SELECT tier, notified FROM messages")[0] == ("today", None)
    llm.reply.update(tier="now", emergency=True)
    c = FolderIMAP()
    a.handle(c, 2, LIST_MAIL.replace(b"<inv1@", b"<inv2@"))
    assert c.moves == [] and notify.sent


def test_the_model_files_topic_mail_the_rules_miss(env):
    triage, llm, _ = env
    triage.CFG["folders"] = {"Club": {**CLUB["Club"], "about": "the club's business"}}
    assert "Club: the club's business" in triage.schema()["properties"]["folder"]["description"]
    a = triage.Account({"user": "a@x.com", "host": "h", "password_env": "P"})
    llm.reply.update(tier="today", folder="Club")
    c = FolderIMAP()
    a.handle(c, 1, RAW)   # nothing on it says club
    assert c.moves == [([1], "Club")]
    llm.reply.update(tier="today", folder="Elsewhere")   # a folder that does not exist is ignored
    c = FolderIMAP()
    a.handle(c, 2, RAW.replace(b"Message-ID: <", b"Message-ID: <x"))
    assert c.moves == []


def test_filed_list_mail_is_not_gone(env):
    triage = env[0]
    triage.CFG["folders"] = CLUB
    triage.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier,applied) VALUES (?,?,?,?,?,?,1)",
             "a@x.com", "<inv1@vendor.com>", triage.now().isoformat(), "s@x", "s", "today")

    class C:
        def folder_exists(self, f): return True
        def select_folder(self, f, readonly=False): self.f = f
        def search(self, crit): return [1]
        def fetch(self, uids, parts):
            ids = {"Club": "<inv1@vendor.com>"}.get(self.f, "<other@x>")
            return {1: {b"BODY[HEADER.FIELDS (MESSAGE-ID)]": f"Message-ID: {ids}\r\n".encode()}}
    a = triage.Account({"user": "a@x.com", "host": "h", "password_env": "P"})
    a.scan_corrections(C())
    assert triage.q("SELECT gone_at, corrected FROM messages")[0] == (None, None)


def test_a_move_waits_until_delivery_has_settled(env, monkeypatch):
    triage, llm, _ = env
    llm.reply.update(tier="later")
    slept = []
    monkeypatch.setattr(triage.time, "sleep", slept.append)
    a = triage.Account({"user": "a@x.com", "host": "h", "password_env": "P"})
    a.seen_at = triage.time.time()   # just seen
    c = FolderIMAP()
    a.handle(c, 1, RAW)
    assert c.moves == [([1], "Later")] and slept and 10 < slept[0] <= 15
    a.seen_at, slept[:] = triage.time.time() - 60, []
    a.handle(c, 2, RAW.replace(b"Subject:", b"Message-ID: <two@x>\r\nSubject:"))
    assert slept == []
