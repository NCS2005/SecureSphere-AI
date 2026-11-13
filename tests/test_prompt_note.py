"""
Tests for the placeholder instruction added to cloud-model requests. No network: httpx.AsyncClient
is replaced with a fake that records the JSON payload.
Run from the project root:  python tests/test_prompt_note.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gateway.router as router
from gateway.config import settings

WITH_TOKEN = "Dear Mr. [TOKEN_HMAC_PERS_RG64QDXIPFGK6], your fee is [CKKS_NUM_4a764ede_1]."
WITH_CKKS_ONLY = "Add [CKKS_NUM_4a764ede_1] and [CKKS_NUM_4a764ede_2]."
WITHOUT = "Write a short poem about the sea. Items in [brackets] or TOKEN_X are not placeholders."


class _Resp:
    status_code = 200
    text = ""

    def __init__(self, kind):
        self.kind = kind

    def json(self):
        if self.kind == "gemini":
            return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
        if self.kind == "openai":
            return {"choices": [{"message": {"content": "ok"}}]}
        return {"response": "ok"}


def _fake_client(sent):
    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            sent.append({"url": url, "json": json})
            kind = "gemini" if "generativelanguage" in url else "openai" if "openai" in url else "ollama"
            return _Resp(kind)
    return FakeClient


class _Env:
    """Temporarily point settings/httpx at the fake so no network is touched."""
    def __init__(self, gemini="", openai="", mock=False, bypass=False):
        self.vals = {"GEMINI_API_KEY": gemini, "OPENAI_API_KEY": openai, "MOCK_CLOUD": mock,
                     "BYPASS_PII_ROUTING": bypass}

    def __enter__(self):
        self.sent = []
        self.saved = {k: getattr(settings, k) for k in self.vals}
        for k, v in self.vals.items():
            setattr(settings, k, v)
        self.saved_client = router.httpx.AsyncClient
        router.httpx.AsyncClient = _fake_client(self.sent)
        return self

    def __exit__(self, *a):
        router.httpx.AsyncClient = self.saved_client
        for k, v in self.saved.items():
            setattr(settings, k, v)


def test_note_text_is_the_requested_instruction():
    n = router.PLACEHOLDER_NOTE
    assert n.startswith("The text contains placeholders in square brackets")
    assert "[TOKEN_...]" in n and "[CKKS_NUM_...]" in n
    assert "Copy it exactly as written, never invent, expand or blank it out." in n


def test_placeholder_note_helper():
    assert router.placeholder_note(WITH_TOKEN) == router.PLACEHOLDER_NOTE
    assert router.placeholder_note(WITH_CKKS_ONLY) == router.PLACEHOLDER_NOTE
    assert router.placeholder_note(WITHOUT) == ""
    assert router.placeholder_note("") == ""


def test_every_placeholder_format_is_recognised():
    formats = [
        "[TOKEN_HMAC_PERS_RG64QDXIPFGK6]",      # HMAC pseudonym (base32)
        "[CKKS_NUM_4a764ede_1]",                # real CKKS
        "[TOKEN_CKKS_NUM_3141_A1B2C3]",         # affine masking, uppercase hash
        "[TOKEN_CKKS_NUM_3141_a1b2c3]",         # affine masking, lowercase hash
        "[TOKEN_NUM_1a2b3c4d]",                 # affine fallback for unparseable numbers (lowercase hex)
        "[TOKEN_NUM_1A2B3C4D]",
    ]
    for f in formats:
        assert router.placeholder_note(f"Please summarise {f} for me") == router.PLACEHOLDER_NOTE, f


def test_generated_tokens_are_recognised():
    """Formats come from the real generators, not just from hand-written examples."""
    import gateway.pii_detector as pd
    generated = [
        pd.pseudonymizer.pseudonymize("Anil Kumar", "PERSON"),
        pd.numerical_engine.mask_numeric("85,000")[0],
        pd.numerical_engine.mask_numeric("not a number")[0],
    ]
    for tok in generated:
        assert router.placeholder_note(f"Value: {tok}") == router.PLACEHOLDER_NOTE, tok


def test_near_miss_brackets_are_not_placeholders():
    for text in ["[TOKEN_]", "[CKKS_NUM_xyz]", "[CKKS_NUM_4a764ede]", "[token_abc]", "[TOKEN_HMAC_PERS_ABC", "TOKEN_NUM_1a2b3c4d"]:
        assert router.placeholder_note(text) == "", text


def test_gemini_adds_system_instruction_only_with_placeholders():
    with _Env(gemini="k") as e:
        asyncio.run(router.call_cloud_llm(WITH_TOKEN))
        p = e.sent[-1]["json"]
        assert p["systemInstruction"]["parts"][0]["text"] == router.PLACEHOLDER_NOTE
        assert p["contents"][0]["parts"][0]["text"] == WITH_TOKEN  # user text untouched
        asyncio.run(router.call_cloud_llm(WITHOUT))
        assert "systemInstruction" not in e.sent[-1]["json"]


def test_openai_adds_system_message_only_with_placeholders():
    with _Env(openai="k") as e:
        asyncio.run(router.call_cloud_llm(WITH_CKKS_ONLY))
        msgs = e.sent[-1]["json"]["messages"]
        assert msgs[0] == {"role": "system", "content": router.PLACEHOLDER_NOTE}
        assert msgs[1] == {"role": "user", "content": WITH_CKKS_ONLY}
        asyncio.run(router.call_cloud_llm(WITHOUT))
        assert e.sent[-1]["json"]["messages"] == [{"role": "user", "content": WITHOUT}]


def test_multimodal_gets_note_only_with_placeholders():
    with _Env(gemini="k") as e:
        asyncio.run(router.call_cloud_multimodal(WITH_TOKEN, "AAAA"))
        assert e.sent[-1]["json"]["systemInstruction"]["parts"][0]["text"] == router.PLACEHOLDER_NOTE
        asyncio.run(router.call_cloud_multimodal(WITHOUT, "AAAA"))
        assert "systemInstruction" not in e.sent[-1]["json"]


def test_local_model_request_is_unchanged():
    with _Env() as e:
        asyncio.run(router.call_local_llm(WITH_TOKEN))
        payload = e.sent[-1]["json"]
        assert payload["prompt"] == WITH_TOKEN
        assert set(payload) == {"model", "prompt", "stream"}, payload
        # PII routing still sends the sanitized prompt to the local model, with no note.
        asyncio.run(router.route_request("orig", WITH_TOKEN, True))
        assert e.sent[-1]["json"]["prompt"] == WITH_TOKEN
        assert "ollama" not in e.sent[-1]["url"] or "generate" in e.sent[-1]["url"]
        assert not any("generativelanguage" in x["url"] or "openai" in x["url"] for x in e.sent)


def test_mock_cloud_mode_unchanged():
    with _Env(mock=True) as e:
        out = asyncio.run(router.call_cloud_llm(WITH_TOKEN))
        assert out.startswith("[Cloud LLM (Mock GPT-4o)]")
        assert e.sent == []


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as ex:
                failed += 1
                print("FAIL", name, "-", f"{type(ex).__name__}: {ex}")
    sys.exit(1 if failed else 0)
