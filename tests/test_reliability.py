"""An urgent push survives a dropped IMAP connection, a failed push and a dead classifier;
a refused login is not hammered."""
import pytest
from imapclient.exceptions import IMAPClientAbortError, LoginError

RAW = (b"From: Mom <mom@example.com>\r\nTo: a@x.com\r\nSubject: Call me now\r\n"
       b"Message-ID: <m1@example.com>\r\n\r\nPlease call.")
SPEC = {"user": "a@x.com", "host": "h", "password_env": "P"}


class DroppingIMAP:
    """An INBOX with one new message (uid 5) whose connection is dead for the first `drops`
    flag or move commands."""
    def __init__(self, drops=0):
        self.drops, self.flags, self.moves = drops, [], []
    def select_folder(self, f, readonly=False): return {b"UIDVALIDITY": 1}
    def search(self, crit): return [5]
    def folder_exists(self, f): return True
    def fetch(self, uids, parts): return {5: {b"BODY[]<0>": RAW}} if b"BODY.PEEK[]" in str(parts).encode() else {}
    def _act(self, log, what):
        if self.drops:
            self.drops -= 1
            raise IMAPClientAbortError("socket error: EOF")
        log.append(what)
    def add_flags(self, uids, flags): self._act(self.flags, uids)
    def move(self, uids, dest): self._act(self.moves, (uids, dest))


def account(triage):
    triage.q("INSERT INTO cursor VALUES ('a@x.com', 1, 4)")
    return triage.Account(SPEC)


def cursor(triage):
    return triage.q("SELECT last_uid FROM cursor")[0][0]


def test_an_urgent_push_goes_out_even_if_imap_drops_and_is_not_repeated(env):
    triage, llm, notify = env
    llm.reply.update(tier="now")
    a, c = account(triage), DroppingIMAP(drops=1)
    with pytest.raises(IMAPClientAbortError):   # the session ends; run() reconnects
        a.process_new(c)
    assert len(notify.sent) == 1 and notify.sent[0][2] == "urgent"
    assert triage.q("SELECT tier, notified, applied, reason FROM messages") == [("now", "sent", 0, "r")]
    assert cursor(triage) == 4   # not advanced: the message is read again
    a.process_new(c)   # the next session
    assert len(notify.sent) == 1 and len(llm.calls) == 1   # no second push, no second model call
    assert c.flags == [[5]] and cursor(triage) == 5
    assert triage.q("SELECT applied FROM messages") == [(1,)]


def test_a_move_lost_to_a_dropped_connection_is_finished_on_the_retry(env, monkeypatch):
    triage, llm, _ = env
    monkeypatch.setitem(triage.CFG, "move_after", 0)
    llm.reply.update(tier="later")
    a, c = account(triage), DroppingIMAP(drops=1)
    with pytest.raises(IMAPClientAbortError):
        a.process_new(c)
    a.process_new(c)
    assert c.moves == [([5], "Later")] and triage.q("SELECT tier, applied FROM messages") == [("later", 1)]


def test_a_connection_that_keeps_dropping_on_one_message_does_not_block_the_account(env):
    triage, llm, notify = env
    llm.reply.update(tier="now")
    a, c = account(triage), DroppingIMAP(drops=99)
    for _ in range(2):
        with pytest.raises(IMAPClientAbortError):
            a.process_new(c)
    a.process_new(c)   # third pass: recorded and pushed long ago, the flag is given up
    assert cursor(triage) == 5 and len(notify.sent) == 1 and a.unfiled == {}


def test_an_imap_error_that_is_not_a_dropped_connection_still_advances(env):
    triage, llm, notify = env
    llm.reply.update(tier="now")
    a, c = account(triage), DroppingIMAP()
    c.add_flags = lambda uids, flags: (_ for _ in ()).throw(triage.IMAPClient.Error("NO flags"))
    a.process_new(c)
    assert cursor(triage) == 5 and len(notify.sent) == 1
    assert triage.q("SELECT tier, notified FROM messages") == [("now", "sent")]


class Stop(Exception):
    pass


def tick(triage, monkeypatch):
    """One pass of the scheduler loop."""
    def stop(_):
        raise Stop
    monkeypatch.setattr(triage.time, "sleep", stop)
    with pytest.raises(Stop):
        triage.scheduler()


def test_a_failed_urgent_push_is_retried_a_few_times_then_left_failed(env, monkeypatch):
    triage, llm, notify = env
    monkeypatch.setitem(triage.CFG, "digest_time", None)
    llm.reply.update(tier="now", emergency=True)
    tries = []
    monkeypatch.setattr(notify, "send", lambda title, msg, level, url=None: tries.append(level) and False)
    a = triage.Account(SPEC)
    a.handle(DroppingIMAP(), 5, RAW)
    state = lambda: triage.q("SELECT notified FROM messages")[0][0]  # noqa: E731
    assert state() not in ("sent", "failed") and len(tries) == 1
    tick(triage, monkeypatch)
    assert len(tries) == 1   # not yet: retries are spaced out
    clock = [triage.time.time()]
    monkeypatch.setattr(triage.time, "time", lambda: clock[0])
    for n in (2, 3, 4):
        clock[0] += 1801
        tick(triage, monkeypatch)
        assert len(tries) == n
    assert state() == "failed" and set(tries) == {"emergency"}
    clock[0] += 86400
    tick(triage, monkeypatch)
    assert len(tries) == 4   # capped


def test_a_retried_push_that_gets_through_is_marked_sent(env, monkeypatch):
    triage, llm, notify = env
    monkeypatch.setitem(triage.CFG, "digest_time", None)
    llm.reply.update(tier="now")
    monkeypatch.setattr(notify, "send", lambda title, msg, level, url=None: False)
    triage.Account(SPEC).handle(DroppingIMAP(), 5, RAW)
    monkeypatch.undo()
    monkeypatch.setitem(triage.CFG, "digest_time", None)
    triage._retry_at.clear()   # as after a restart: tried at once
    tick(triage, monkeypatch)
    assert triage.q("SELECT notified FROM messages") == [("sent",)]
    assert len(notify.sent) == 1 and "delayed" in notify.sent[0][1]


def test_deadman_goes_down_when_the_classifier_keeps_failing_and_recovers(env, monkeypatch):
    triage, llm, _ = env
    monkeypatch.setattr(triage, "STARTED", triage.time.time() - 3600)
    monkeypatch.setitem(triage.LAST_OK, "a@x.com", triage.time.time())
    good = llm.classify

    def broken(system, user, schema):
        raise PermissionError("invalid x-api-key")
    a, c = triage.Account(SPEC), DroppingIMAP()
    llm.classify = broken
    for n in range(3):
        assert triage.deadman_status()[0] == "up"
        a.handle(c, n, RAW.replace(b"<m1@", f"<f{n}@".encode()))
    status, msg = triage.deadman_status()
    assert status == "down" and "classifier" in msg and "PermissionError" in msg and "x-api-key" not in msg
    llm.classify = good
    a.handle(c, 9, RAW.replace(b"<m1@", b"<ok@"))
    assert triage.deadman_status()[0] == "up"


def run_until(triage, monkeypatch, a, error, sleeps):
    """Run the account loop with every session failing; stop after `sleeps` waits."""
    slept = []

    def sleep(s):
        slept.append(s)
        if len(slept) == sleeps:
            raise Stop

    def session():
        raise error
    monkeypatch.setattr(triage.time, "sleep", sleep)
    monkeypatch.setattr(a, "session", session)
    with pytest.raises(Stop):
        a.run()
    return slept


def test_a_refused_login_alerts_once_and_backs_off_to_hours(env, monkeypatch):
    triage, _, notify = env
    a = triage.Account(SPEC)
    slept = run_until(triage, monkeypatch, a, LoginError("[AUTHENTICATIONFAILED] Invalid credentials"), 6)
    assert slept == [3600, 7200, 14400, 28800, 43200, 43200]
    assert [t for t, _, _ in notify.sent] == ["mail-triage: login refused"]
    assert "a@x.com" in notify.sent[0][1]


def test_network_errors_keep_the_short_backoff(env, monkeypatch):
    triage, _, notify = env
    for error in (OSError("connection reset"), LoginError("[UNAVAILABLE] Temporary authentication failure")):
        slept = run_until(triage, monkeypatch, triage.Account(SPEC), error, 6)
        assert slept == [30, 60, 120, 240, 480, 600] and not notify.sent
