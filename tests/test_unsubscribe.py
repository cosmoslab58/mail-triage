"""Unsubscribing: the right method for each kind of header, and never inside the network."""
import datetime as dt
import socket

import pytest

import actions
import unsubscribe as unsub


def hdrs(unsubscribe="", post=""):
    out = "Date: Fri, 23 Oct 2026 10:00:00 -0400\r\n"
    if unsubscribe:
        out += f"List-Unsubscribe: {unsubscribe}\r\n"
    if post:
        out += f"List-Unsubscribe-Post: {post}\r\n"
    return (out + "\r\n").encode()


class Box:
    """A mailbox with one message from the sender, in Later."""
    def __init__(self, raw):
        self.raw, self.sel, self.searched = raw, None, []

    def folder_exists(self, f):
        return True

    def select_folder(self, f, readonly=False):
        self.sel = f

    def search(self, crit):
        self.searched.append(crit)
        return [9] if self.sel == "Later" else []

    def fetch(self, uids, parts):
        return {9: {b"INTERNALDATE": dt.datetime(2026, 10, 23), unsub.HEADERS: self.raw}}

    def logout(self):
        pass


@pytest.fixture
def ax(env, monkeypatch):
    triage, _, _ = env
    actions.triage = triage
    monkeypatch.setattr(unsub, "public_https", lambda url: url.startswith("https://lists."))
    return triage


def test_one_click_posts_and_is_recorded(ax):
    posted = []

    class Opener:
        def open(self, req, timeout):
            posted.append((req.full_url, req.data, req.get_method()))

            class R:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *a): pass
            return R()
    box = Box(hdrs("<https://lists.shop.example/u/1>, <mailto:u@shop.example>", "List-Unsubscribe=One-Click"))
    out = actions.unsubscribe("a@x.com", "News@Shop.example", connect=lambda: box, post=Opener())
    assert out["method"] == "one-click"
    assert posted == [("https://lists.shop.example/u/1", b"List-Unsubscribe=One-Click", "POST")]
    assert ax.q("SELECT sender, method FROM unsubscribed") == [("news@shop.example", "one-click")]
    assert box.searched[0][:2] == ["FROM", "news@shop.example"]


def test_mailto_sends_an_email_from_the_account(ax):
    sent = []
    box = Box(hdrs("<mailto:leave@shop.example?subject=remove%20me>"))
    out = actions.unsubscribe("a@x.com", "news@shop.example", connect=lambda: box, send=sent.append)
    assert out["method"] == "email" and sent[0]["To"] == "leave@shop.example"
    assert sent[0]["From"] == "a@x.com" and sent[0]["Subject"] == "remove me"


def test_a_plain_link_is_handed_back_to_open(ax):
    out = actions.unsubscribe("a@x.com", "news@shop.example", connect=lambda: Box(hdrs("<https://shop.example/prefs>")))
    assert out["method"] == "link" and out["url"] == "https://shop.example/prefs"


def test_no_header_and_no_mail_are_404s(ax):
    for box in (Box(hdrs()), type("Empty", (Box,), {"search": lambda self, crit: []})(hdrs())):
        with pytest.raises(actions.ActionError) as e:
            actions.unsubscribe("a@x.com", "news@shop.example", connect=lambda b=box: b)
        assert e.value.status == 404


def test_phishing_senders_and_bad_addresses_are_refused(ax):
    ax.q("INSERT INTO messages (account,msgid,ts,sender,subject,tier,phishing) VALUES (?,?,?,?,?,?,?)",
         "a@x.com", "<p@1>", "2026-10-23", "fake@amex.example", "Verify", "later", 1)
    with pytest.raises(actions.ActionError) as e:
        actions.unsubscribe("a@x.com", "fake@amex.example", connect=lambda: Box(hdrs("<https://lists.x/u>")))
    assert e.value.status == 403
    for bad in ("", "a@b\r\nX1 NOOP", "no-at-sign", None):
        with pytest.raises(actions.ActionError) as e:
            actions.unsubscribe("a@x.com", bad, connect=lambda: Box(hdrs()))
        assert e.value.status == 400


def test_one_click_never_reaches_inside_the_network(monkeypatch):
    def resolve(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ({"inside.example": "192.168.4.113",
                 "loop.example": "127.0.0.1"}.get(host, "93.184.216.34"), 443))]
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    assert unsub.public_https("https://lists.shop.example/u")
    for url in ("https://inside.example/u", "https://loop.example/u", "http://lists.shop.example/u",
                "https://10.0.0.1/u", "javascript:alert(1)"):
        assert not unsub.public_https(url), url
    with pytest.raises(unsub.UnsubError):
        unsub.one_click("https://inside.example/u")
