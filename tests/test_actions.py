"""Moves go through IMAP and are recorded as corrections; the API refuses without its token."""
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

    def find_special_folder(self, flag):
        return self.junk if self.junk in self.folders else None

    def folder_exists(self, f):
        return f in self.folders

    def select_folder(self, f, readonly=False):
        self.sel = f

    def search(self, crit):
        if crit[0] == "HEADER":
            return [u for u, raw in self.folders[self.sel].items() if crit[2].encode() in raw]
        return list(self.folders[self.sel])

    def fetch(self, uids, parts):
        return {u: {HDR: self.folders[self.sel][u]} for u in uids}

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


def test_read_only_account_only_moves_to_inbox(ax):
    with pytest.raises(actions.ActionError) as e:
        actions.move("ro@x.com", "<a@1>", "spam", connect=box)
    assert e.value.status == 403


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
