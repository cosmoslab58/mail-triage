"""The Anthropic provider sends fallbacks only when configured, through the beta endpoint."""
from types import SimpleNamespace

import providers


class FakeMessages:
    def __init__(self):
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text='{"tier": "later"}')])


def provider(cfg):
    p = providers.make({"provider": "anthropic", "model": "claude-opus-5-5", "api_key_env": "X"} | cfg)
    plain, beta = FakeMessages(), FakeMessages()
    p._client = SimpleNamespace(messages=plain, beta=SimpleNamespace(messages=beta))
    return p, plain, beta


def test_plain_request_without_fallbacks():
    p, plain, beta = provider({"effort": "low"})
    assert p.classify("sys", "mail", {"type": "object"}) == {"tier": "later"}
    assert not beta.calls and plain.calls[0]["output_config"]["effort"] == "low"
    assert "fallbacks" not in plain.calls[0]


def test_fallbacks_go_through_the_beta_endpoint():
    p, plain, beta = provider({"fallbacks": "default"})
    p.classify("sys", "mail", {"type": "object"})
    assert not plain.calls
    assert beta.calls[0]["fallbacks"] == "default"
    assert beta.calls[0]["betas"] == ["server-side-fallback-2026-07-01"]
