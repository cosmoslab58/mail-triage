"""LLM backends. Each takes (system, user, schema) and returns the parsed JSON object.

  gemini     Google Gemini via google-genai            (api_key_env default GOOGLE_API_KEY)
  anthropic  Claude via the anthropic SDK              (api_key_env default ANTHROPIC_API_KEY)
  openai     anything OpenAI-compatible: OpenAI itself, Ollama, OpenRouter, vLLM, LM Studio
             (set base_url for anything but OpenAI; api_key_env default OPENAI_API_KEY)

SDKs are imported lazily, so only the one you use has to be installed.
"""
import json
import os


class Provider:
    default_key_env = None

    def __init__(self, cfg):
        self.cfg = cfg
        self.model = cfg["model"]
        self.api_key = os.environ.get(cfg.get("api_key_env") or self.default_key_env or "", "") or None
        self._client = None

    def classify(self, system, user, schema):
        raise NotImplementedError


class Gemini(Provider):
    default_key_env = "GOOGLE_API_KEY"

    def classify(self, system, user, schema):
        from google import genai
        from google.genai import types
        if self._client is None:
            self._client = genai.Client(api_key=self.api_key)
        config = {"system_instruction": system, "response_mime_type": "application/json",
                  "response_json_schema": schema}
        if self.cfg.get("thinking"):
            config["thinking_config"] = types.ThinkingConfig(thinking_level=self.cfg["thinking"])
        resp = self._client.models.generate_content(
            model=self.model, contents=user, config=types.GenerateContentConfig(**config))
        if not resp.text:
            raise RuntimeError(f"gemini returned nothing: {resp.candidates and resp.candidates[0].finish_reason}")
        return json.loads(resp.text)


class Anthropic(Provider):
    default_key_env = "ANTHROPIC_API_KEY"

    def classify(self, system, user, schema):
        import anthropic
        if self._client is None:
            self._client = anthropic.Anthropic(api_key=self.api_key)
        output_config = {"format": {"type": "json_schema", "schema": schema}}
        if self.cfg.get("effort"):
            output_config["effort"] = self.cfg["effort"]
        resp = self._client.messages.create(
            model=self.model, max_tokens=4000, system=system,
            messages=[{"role": "user", "content": user}], output_config=output_config)
        if resp.stop_reason != "end_turn":
            raise RuntimeError(f"claude stop_reason={resp.stop_reason}")
        return json.loads(next(b.text for b in resp.content if b.type == "text"))


class OpenAICompatible(Provider):
    default_key_env = "OPENAI_API_KEY"

    def classify(self, system, user, schema):
        import openai
        if self._client is None:
            # Local servers such as Ollama ignore the key but the SDK insists on one.
            self._client = openai.OpenAI(api_key=self.api_key or "unused", base_url=self.cfg.get("base_url"))
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={"type": "json_schema",
                             "json_schema": {"name": "triage", "schema": schema, "strict": True}})
        text = resp.choices[0].message.content
        if not text:
            raise RuntimeError(f"model returned nothing: finish_reason={resp.choices[0].finish_reason}")
        return json.loads(text)


TYPES = {"gemini": Gemini, "anthropic": Anthropic, "openai": OpenAICompatible}


def make(cfg):
    try:
        return TYPES[cfg["provider"]](cfg)
    except KeyError:
        raise SystemExit(f"llm.provider must be one of {', '.join(TYPES)}, got {cfg.get('provider')!r}") from None
