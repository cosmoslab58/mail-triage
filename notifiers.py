"""Push notification backends. Each one maps three abstract levels onto its own scale.

  urgent  a "now" email                    (phone should interrupt)
  normal  the daily digest, ops problems   (worth a sound)
  low     the weekly roll-up               (silent)
"""
import json
import logging
import os
import urllib.parse
import urllib.request

log = logging.getLogger("triage")

LEVELS = ("urgent", "normal", "low")


def _post(url, body, headers, form=False):
    data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
    ctype = "application/x-www-form-urlencoded" if form else "application/json"
    req = urllib.request.Request(url, data, {"Content-Type": ctype, **headers})
    urllib.request.urlopen(req, timeout=15).read()


class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg or {}

    def secret(self, key):
        name = self.cfg.get(key)
        return os.environ.get(name, "") if name else ""

    def send(self, title, message, level="normal"):
        if level not in LEVELS:
            raise ValueError(f"unknown level {level!r}")
        try:
            self._send(title, message, level)
            return True
        except Exception as e:
            log.error("%s push failed: %s", self.cfg.get("type"), e)
            return False

    def _send(self, title, message, level):
        raise NotImplementedError


class Gotify(Notifier):
    # Gotify Android buckets priorities into channels: 0 Min, 1-3 Low, 4-7 Normal, 8-10 High.
    PRIORITY = {"urgent": 8, "normal": 5, "low": 2}

    def _send(self, title, message, level):
        _post(self.cfg["url"].rstrip("/") + "/message",
              {"title": title, "message": message, "priority": self.PRIORITY[level],
               "extras": {"client::display": {"contentType": "text/markdown"}}},
              {"X-Gotify-Key": self.secret("token_env")})


class Ntfy(Notifier):
    # ntfy priorities: 5 max/urgent, 4 high, 3 default, 2 low, 1 min.
    PRIORITY = {"urgent": 5, "normal": 3, "low": 2}

    def _send(self, title, message, level):
        headers = {}
        token = self.secret("token_env")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        _post(self.cfg.get("url", "https://ntfy.sh").rstrip("/"),
              {"topic": self.cfg["topic"], "title": title, "message": message,
               "priority": self.PRIORITY[level], "markdown": True}, headers)


class Pushover(Notifier):
    PRIORITY = {"urgent": 1, "normal": 0, "low": -1}

    def _send(self, title, message, level):
        _post("https://api.pushover.net/1/messages.json",
              {"token": self.secret("token_env"), "user": self.secret("user_env"),
               "title": title, "message": message, "priority": self.PRIORITY[level]},
              {}, form=True)


class Log(Notifier):
    """type: none. Logs what would have been pushed; handy for a first dry run."""

    def _send(self, title, message, level):
        log.info("[notify %s] %s | %s", level, title, message.replace("\n", " / ")[:300])


TYPES = {"gotify": Gotify, "ntfy": Ntfy, "pushover": Pushover, "none": Log}


def make(cfg):
    cfg = cfg or {"type": "none"}
    try:
        return TYPES[cfg["type"]](cfg)
    except KeyError:
        raise SystemExit(f"notify.type must be one of {', '.join(TYPES)}, got {cfg.get('type')!r}") from None
