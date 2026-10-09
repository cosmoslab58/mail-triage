import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import triage  # noqa: E402


class FakeLLM:
    def __init__(self):
        self.reply = {"tier": "today", "category": "test", "summary": "s", "reason": "r", "phishing": False}
        self.calls = []

    def classify(self, system, user, schema):
        self.calls.append((system, user, schema))
        return dict(self.reply)


class FakeNotify:
    def __init__(self):
        self.sent = []

    def send(self, title, message, level="normal"):
        self.sent.append((title, message, level))
        return True


@pytest.fixture
def env(tmp_path):
    profile = tmp_path / "profile.md"
    profile.write_text("Bills matter.")
    cfg = {**triage.DEFAULTS, "owner": "Alex", "timezone": "UTC", "profile": profile,
           "llm": {"provider": "gemini", "model": "x"},
           "accounts": [{"user": "a@x.com", "host": "h", "password_env": "P"}]}
    llm, notify = FakeLLM(), FakeNotify()
    triage.init(cfg, tmp_path / "data", llm=llm, notify=notify)
    return triage, llm, notify
