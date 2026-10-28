"""Moves go through IMAP and are recorded as corrections; the API refuses without its token."""
import datetime as dt
import json
import urllib.error
import urllib.request

import pytest

import actions

HDR = actions.HEADERS


class FakeIMAP:
    """Folders of {uid: raw headers}; just enough of IMAPClient for actions.py."""

    def __init__(self, folders, junk="[Gmail]/Spam"):
        self.folders, self.junk, self.sel, self.moves = folders, junk, None, []
        self.seen, self.readonly = set(), {}   # (folder, uid) that are read; folder -> last select mode

    def find_special_folder(self, flag):
        return self.junk if self.junk in self.folders else None

    def folder_exists(self, f):
        return f in self.folders

    def select_folder(self, f, readonly=False):
        self.sel = f
        self.readonly[f] = readonly

    def has_capability(self, cap):
        return False

    def search(self, crit, charset=None):
        if crit[0] == "UID":
            have = sorted(self.folders[self.sel])
            if crit[1] == "*":
                return have[-1:]
            lo, hi = map(int, crit[1].split(":"))
            return [u for u in have if lo <= u <= hi]
        if crit[0] == "HEADER":
            return [u for u, raw in self.folders[self.sel].items() if crit[2].encode() in raw]
        words = [crit[i + 1] for i, c in enumerate(crit) if c == "TEXT"]
        return [u for u, raw in self.folders[self.sel].items() if all(w.lower().encode() in raw.lower() for w in words)]

    def fetch(self, uids, parts):
        return {u: {HDR: self.folders[self.sel][u], actions.HEADERS_TO: self.folders[self.sel][u],
                    b"BODY[]": self.folders[self.sel][u],
                    b"FLAGS": (actions.SEEN,) if (self.sel, u) in self.seen else ()} for u in uids}

    def add_flags(self, uids, flags):
        assert not self.readonly[self.sel]
        self.seen.update((self.sel, u) for u in uids)

    def remove_flags(self, uids, flags):
        assert not self.readonly[self.sel]
        self.seen.difference_update((self.sel, u) for u in uids)

    def move(self, uids, dest):
        for u in uids:
            self.folders[dest][u + 100] = self.folders[self.sel].pop(u)
        self.moves.append((self.sel, dest))

    def logout(self):
        pass


def raw(msgid, subj="Hello", frm="Jo <jo@example.com>"):
    return f"From: {frm}\r\nSubject: {subj}\r\nDate: Fri, 09 Oct 2026 10:00:00 -0400\r\nMessage-ID: {msgid}\r\n\r\n".encode()


@pytest.fixture
def ax(env):
    triage, _, _ = env
    actions.triage = triage
    triage.CFG["accounts"].append({"user": "ro@x.com", "host": "h", "password_env": "P", "move": False})
    return triage


def box():
    return FakeIMAP({"INBOX": {1: raw("<a@1>")}, "Later": {}, "[Gmail]/Spam": {7: raw("<s@1>", "You won")}})


def test_inbox_to_later_records_the_correction(ax):
    ax.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier) VALUES (?,?,?,?,?,?)",
         "a@x.com", "<a@1>", "2026-10-09", "jo@example.com", "Hello", "today")
    imap = box()
    out = actions.move("a@x.com", "<a@1>", "later", connect=lambda: imap)
    assert out["moved_from"] == "INBOX" and imap.moves == [("INBOX", "Later")]
    assert ax.q("SELECT corrected FROM messages WHERE msgid='<a@1>'") == [("later",)]


def test_moving_back_to_its_own_tier_clears_the_correction(ax):
    ax.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier,corrected) VALUES (?,?,?,?,?,?,?)",
         "a@x.com", "<a@1>", "2026-10-09", "jo@example.com", "Hello", "later", "today")
    imap = FakeIMAP({"INBOX": {1: raw("<a@1>")}, "Later": {}, "[Gmail]/Spam": {}})
    actions.move("a@x.com", "<a@1>", "later", connect=lambda: imap)
    assert ax.q("SELECT corrected FROM messages WHERE msgid='<a@1>'") == [(None,)]


def test_rescue_from_spam_is_recorded_before_it_reaches_the_inbox(ax):
    imap = box()
    actions.move("a@x.com", "<s@1>", "inbox", connect=lambda: imap)
    assert imap.moves == [("[Gmail]/Spam", "INBOX")]
    row = ax.q("SELECT tier, corrected, subject, digested FROM messages WHERE msgid='<s@1>'")
    assert row == [("spam", "today", "You won", 1)]   # the watcher skips known msgids


def test_shared_box_can_be_moved_by_hand(ax):
    assert actions.move("ro@x.com", "<a@1>", "later", connect=box)["moved_to"] == "Later"
    assert actions.move("ro@x.com", "<a@1>", "spam", connect=box)["moved_to"] == "[Gmail]/Spam"


def test_missing_message_is_410_and_marked_gone(ax):
    ax.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier) VALUES (?,?,?,?,?,?)",
         "a@x.com", "<nope@1>", "2026-10-09", "jo@example.com", "deleted", "today")
    with pytest.raises(actions.ActionError) as e:
        actions.move("a@x.com", "<nope@1>", "later", connect=box)
    assert e.value.status == 410
    assert ax.q("SELECT gone_at IS NOT NULL FROM messages WHERE msgid='<nope@1>'") == [(1,)]


def test_already_in_place_is_ok(ax):
    assert actions.move("a@x.com", "<a@1>", "inbox", connect=box)["moved_from"] is None


def test_spam_listing(ax):
    items = actions.spam_for({"user": "a@x.com"}, 30, connect=box)
    assert [(m["msgid"], m["subject"], m["sender"]) for m in items] == [("<s@1>", "You won", "jo@example.com")]


def test_api_needs_the_token(ax, monkeypatch):
    monkeypatch.setenv("T", "secret")
    server = actions.start({"listen": "127.0.0.1:0", "token_env": "T"}, ax)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"{url}/accounts")
        assert e.value.code == 401
        req = urllib.request.Request(f"{url}/accounts", headers={"Authorization": "Bearer secret"})
        users = json.load(urllib.request.urlopen(req))
        assert {"user": "ro@x.com", "move": False} in users
    finally:
        server.shutdown()


def test_api_off_without_token(ax, monkeypatch):
    monkeypatch.delenv("T", raising=False)
    assert actions.start({"listen": "127.0.0.1:0", "token_env": "T"}, ax) is None
    assert actions.start(None, ax) is None


def test_message_is_readable_text(ax):
    html_mail = (b"From: Jo <jo@example.com>\r\nSubject: Lunch\r\nMessage-ID: <h@1>\r\n"
                 b"Content-Type: text/html\r\n\r\n<style>p{}</style><p>Hi&nbsp;there</p><p>Lunch<br>Friday?</p>")
    imap = FakeIMAP({"INBOX": {}, "Later": {3: html_mail}, "[Gmail]/Spam": {}})
    out = actions.message("a@x.com", "<h@1>", connect=lambda: imap)
    assert out["folder"] == "Later" and out["subject"] == "Lunch"
    assert out["text"] == "Hi there\nLunch\nFriday?"


def test_message_gone_is_410(ax):
    with pytest.raises(actions.ActionError) as e:
        actions.message("a@x.com", "<nope@1>", connect=box)
    assert e.value.status == 410


def test_folder_listing_shows_read_state_without_changing_it(ax):
    imap = FakeIMAP({"INBOX": {1: raw("<a@1>"), 2: raw("<b@1>", "Two")}, "Later": {}, "[Gmail]/Spam": {}})
    imap.seen.add(("INBOX", 1))
    items = actions.listing({"user": "a@x.com"}, "inbox", 14, connect=lambda: imap)
    assert {m["msgid"]: m["seen"] for m in items} == {"<a@1>": True, "<b@1>": False}
    assert imap.readonly["INBOX"] is True


def test_mark_read_and_unread(ax):
    imap = FakeIMAP({"INBOX": {1: raw("<a@1>")}, "Later": {5: raw("<l@1>")}, "[Gmail]/Spam": {}})
    out = actions.set_seen("a@x.com", ["<a@1>", "<l@1>"], True, connect=lambda: imap)
    assert out["changed"] == 2 and imap.seen == {("INBOX", 1), ("Later", 5)}
    actions.set_seen("a@x.com", ["<l@1>"], False, connect=lambda: imap)
    assert imap.seen == {("INBOX", 1)}


def test_shared_box_can_be_marked_read(ax):
    imap = box()
    assert actions.set_seen("ro@x.com", ["<a@1>"], True, connect=lambda: imap)["changed"] == 1


def test_opening_with_read_marks_it_read(ax):
    imap = FakeIMAP({"INBOX": {1: raw("<a@1>")}, "Later": {}, "[Gmail]/Spam": {}})
    assert actions.message("a@x.com", "<a@1>", connect=lambda: imap)["seen"] is False
    assert imap.seen == set()                                   # peeked
    assert actions.message("a@x.com", "<a@1>", read=True, connect=lambda: imap)["seen"] is True
    assert imap.seen == {("INBOX", 1)}


@pytest.mark.parametrize("bad", ["", "<a>\r\nX1 UID MOVE 1:* Trash", "no-brackets", "<a b>", "<é@x>", None])
def test_only_real_message_ids_reach_imap(ax, bad):
    called = []
    for fn in (lambda: actions.message("a@x.com", bad, connect=lambda: called.append(1)),
               lambda: actions.move("a@x.com", bad, "later", connect=lambda: called.append(1)),
               lambda: actions.set_seen("a@x.com", [bad], True, connect=lambda: called.append(1))):
        with pytest.raises(actions.ActionError) as e:
            fn()
        assert e.value.status == 400
    assert not called


def test_bad_days_is_a_400(ax, monkeypatch):
    monkeypatch.setenv("T", "secret")
    server = actions.start({"listen": "127.0.0.1:0", "token_env": "T"}, ax)
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/spam?days=abc",
                                     headers={"Authorization": "Bearer secret"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 400
    finally:
        server.shutdown()


def test_forwarded_message_does_not_replace_the_body(ax):
    from email import message_from_bytes, policy
    raw = (b"From: a@x\r\nMessage-ID: <f@1>\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
           b"--B\r\nContent-Type: text/html\r\n\r\n<p>See below</p>\r\n"
           b"--B\r\nContent-Type: message/rfc822\r\n\r\nFrom: b@y\r\nContent-Type: text/plain\r\n\r\nOld mail\r\n--B--\r\n")
    assert actions.readable(message_from_bytes(raw, policy=policy.default)) == "See below"


def test_mark_read_looks_where_told_and_stops_when_found(ax):
    imap = FakeIMAP({"INBOX": {1: raw("<a@1>")}, "Later": {5: raw("<l@1>")}, "[Gmail]/Spam": {}})
    selected = []
    real = imap.select_folder
    imap.select_folder = lambda f, readonly=False: selected.append(f) or real(f, readonly)
    actions.set_seen("a@x.com", ["<l@1>"], True, where="later", connect=lambda: imap)
    assert selected == ["Later"] and imap.seen == {("Later", 5)}


def test_logins_are_reused_and_dropped_when_broken(ax, monkeypatch):
    made = []

    class Conn(FakeIMAP):
        alive = True
        def noop(self):
            if not self.alive:
                raise OSError("gone")
    def connect(self):
        c = Conn({"INBOX": {1: raw("<a@1>")}, "Later": {}, "[Gmail]/Spam": {}})
        made.append(c)
        return c
    monkeypatch.setattr(ax.Account, "connect", connect)
    actions._pool.clear()
    actions.set_seen("a@x.com", ["<a@1>"], True)
    actions.set_seen("a@x.com", ["<a@1>"], False)
    assert len(made) == 1                       # second call reused the login
    made[0].alive = False
    actions.set_seen("a@x.com", ["<a@1>"], True)
    assert len(made) == 2                       # a dead one is replaced
    actions._pool.clear()


def test_search_finds_mail_in_every_folder_once_and_refuses_junk_queries():
    imap = FakeIMAP({"INBOX": {1: raw("<a@1>", "Your LL Bean order shipped")},
                     "Later": {2: raw("<b@2>", "LL Bean sale"), 3: raw("<c@3>", "Other")}}, junk="none")
    since = dt.date(2026, 1, 1)
    out = actions.search({"user": "a@x.com"}, ["bean"], since, connect=lambda: imap)
    assert {m["msgid"] for m in out} == {"<a@1>", "<b@2>"}
    assert all(imap.readonly[f] for f in imap.readonly)   # searching never marks anything
    assert actions.search({"user": "a@x.com"}, ["bean", "shipped"], since, connect=lambda: imap)[0]["folder"] == "INBOX"
    assert actions.search_terms('x "bean"\r\nA1 LOGOUT') == ["bean", "A1", "LOGOUT"]
    with pytest.raises(actions.ActionError):
        actions.search_terms("  ")


def test_important_is_now_today_inbox_mail_without_a_to_do(ax):
    now = ax.now().isoformat()
    rows = [("<a@1>", "now", None, 0), ("<b@1>", "today", None, 0), ("<c@1>", "later", None, 0),
            ("<d@1>", "today", "later", 0), ("<e@1>", "now", None, 1), ("<f@1>", "today", None, 0)]
    for msgid, tier, corrected, phishing in rows:
        ax.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier,summary,corrected,phishing) VALUES (?,?,?,?,?,?,?,?,?)",
             "a@x.com", msgid, now, "jo@example.com", "S " + msgid, tier, "sum", corrected, phishing)
    ax._db.executescript("CREATE TABLE IF NOT EXISTS dav (uid TEXT, account TEXT, msgid TEXT, kind TEXT, msgids TEXT)")
    ax.q("INSERT INTO dav (uid,account,msgid,kind,msgids) VALUES ('u','a@x.com','<b@1>','todo','<b@1>')")
    inbox = {"items": [{"account": "a@x.com", "msgid": m, "seen": m == "<a@1>"} for m in ("<a@1>", "<b@1>", "<e@1>")],
             "errors": {}}
    out = actions.important(24, folder_fn=lambda name, days: inbox)
    # b has a to-do, c is later, d was moved to Later, e is phishing, f left the inbox
    assert [(m["msgid"], m["seen"]) for m in out["items"]] == [("<a@1>", True)]


class MissingIndex(FakeIMAP):
    """A server whose HEADER search misses messages (Purelymail did, for one in Later)."""

    def search(self, crit, charset=None):
        return [] if crit[0] == "HEADER" else super().search(crit, charset)


def test_mark_read_finds_a_message_the_server_search_misses(ax):
    c = MissingIndex({"INBOX": {}, "Later": {5: raw("<w@1>", "Watchtower"), 6: raw("<other@1>")}, "[Gmail]/Spam": {}})
    out = actions.set_seen("a@x.com", ["<w@1>"], True, where="later", connect=lambda: c)
    assert out == {"ok": True, "changed": 1} and ("Later", 5) in c.seen and ("Later", 6) not in c.seen


def test_the_fallback_reads_only_the_newest_messages_and_never_searches_all(ax, monkeypatch):
    """SEARCH ALL in Gmail's All Mail answered past imaplib's 1 MB limit (2026-10-28)."""
    monkeypatch.setattr(actions, "SCAN", 2)
    c = MissingIndex({"INBOX": {1: raw("<old@1>"), 7: raw("<x@1>"), 8: raw("<w@1>")}})
    c.select_folder("INBOX")
    asked = []
    real = c.search
    c.search = lambda crit, charset=None: asked.append(crit) or real(crit, charset)
    assert actions.search_msgids(c, ["<w@1>", "<old@1>"]) == {"<w@1>": [8]}
    assert ["ALL"] not in asked


def test_gmail_trusts_its_own_search(ax):
    c = MissingIndex({"INBOX": {8: raw("<w@1>")}})
    c.has_capability = lambda cap: cap == "X-GM-EXT-1"
    c.select_folder("INBOX")
    assert actions.search_msgids(c, ["<w@1>"]) == {}


def test_a_busy_account_connection_is_not_waited_on(ax, monkeypatch):
    """One slow request held an account's kept connection and the Mail page queued behind it."""
    monkeypatch.setattr(actions, "LOCK_WAIT_S", 0.1)
    fresh = []
    monkeypatch.setattr(actions.triage, "Account", lambda spec: type("A", (), {"connect": lambda self: fresh.append(1) or box()})())
    lock = actions._lock("a@x.com")
    lock.acquire()
    try:
        with actions.imap({"user": "a@x.com"}) as c:
            assert isinstance(c, FakeIMAP)
    finally:
        lock.release()
    assert fresh == [1] and "a@x.com" not in actions._pool   # its own connection, not kept


def test_the_header_fallback_reads_each_folder_once(ax):
    reads = []

    class Counting(MissingIndex):
        def fetch(self, uids, parts):
            reads.append(len(uids))
            return super().fetch(uids, parts)
    c = Counting({"INBOX": {}, "Later": {i: raw(f"<m{i}@1>") for i in range(1, 6)}, "[Gmail]/Spam": {}})
    out = actions.set_seen("a@x.com", [f"<m{i}@1>" for i in range(1, 6)], True, where="later", connect=lambda: c)
    assert out["changed"] == 5 and reads == [5]   # one pass over Later for all five
