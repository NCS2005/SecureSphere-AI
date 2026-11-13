"""
Tests for the real-CKKS numeric privacy path.
Run from the project root:  python -m pytest tests/test_ckks.py -v
(or)                        python tests/test_ckks.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gateway.pii_detector as pd
from gateway.ckks_engine import ckks_engine, CKKSKeyHolder, CKKSComputeServer, TOKEN_RE
from presidio_analyzer import RecognizerResult

MONEY_RE = re.compile(r"[\$₹]\s*\d{1,3}(?:,\d{3})*(?:\.\d+)?")


def _fake_detect(text):
    """Deterministic MONEY detector so the test does not depend on spaCy models."""
    return [RecognizerResult(entity_type="MONEY", start=m.start(), end=m.end(), score=0.9)
            for m in MONEY_RE.finditer(text)]


def _setup(monkeypatch=None):
    pd.detect_pii = _fake_detect


def test_compute_server_cannot_decrypt_and_rejects_secret_key():
    holder = CKKSKeyHolder()
    try:
        CKKSComputeServer(holder._ctx.serialize(save_secret_key=True))
        assert False, "server accepted a secret key"
    except ValueError:
        pass
    server = CKKSComputeServer(holder.public_context_bytes())
    ct = holder.encrypt(1234.5)
    out = server.evaluate("MUL", [ct], [2])
    assert abs(holder.decrypt(out) - 2469.0) < 1e-3
    try:
        pd.ts if False else None
        import tenseal as ts
        ts.ckks_vector_from(server._ctx, ct).decrypt()
        assert False, "compute server decrypted a ciphertext"
    except ValueError:
        pass


def test_prompt_contains_no_plaintext_numbers_and_roundtrips():
    _setup()
    prompt = "My salary is $1,250,000 and my bonus is $50,000. What is the total and an 18% tax?"
    sanitized, mapping, has_pii = pd.anonymize_prompt(prompt)
    assert has_pii
    assert "1,250,000" not in sanitized and "50,000" not in sanitized
    assert "1,250,000" not in str(mapping) and "50,000" not in str(mapping)
    tokens = TOKEN_RE.findall(sanitized)
    assert len(tokens) >= 2
    toks = re.findall(r"\[CKKS_NUM_[0-9a-f]{8}_\d+\]", sanitized)
    sal = [t for t in toks if t.endswith("_2]")][0]   # processed right-to-left: salary is _2
    bon = [t for t in toks if t.endswith("_1]")][0]
    llm_reply = f"Total: CKKS_SUM({sal}, {bon}). Tax at 18%: CKKS_PCT({sal}, 18). Your salary was {sal}."
    final = pd.deanonymize_response(llm_reply, mapping)
    assert "$1,300,000" in final, final
    assert "$225,000" in final, final
    assert "Your salary was $1,250,000." in final, final


def test_bad_or_unknown_operation_is_left_untouched():
    _setup()
    _, mapping, _ = pd.anonymize_prompt("I earn $100,000.")
    out = pd.deanonymize_response("Try CKKS_SUM(a, b) please", mapping)
    assert out == "Try CKKS_SUM(a, b) please"


def test_precision():
    h = CKKSKeyHolder(); s = CKKSComputeServer(h.public_context_bytes())
    for v in (50000.0, 85000.5, 1250000.0, 9999999.0):
        for f in (0.18, 0.5, 1 / 3):
            got = h.decrypt(s.evaluate("MUL", [h.encrypt(v)], [f]))
            assert abs(got - v * f) < 1e-3, (v, f, got)


def test_affine_fallback_mode_still_available():
    # The original class is untouched and still works (revert path).
    eng = pd.PrivacyPreservingNumericalEngine()
    token, meta = eng.mask_numeric("$50,000")
    assert eng.unmask_numeric(meta["transformed_value"]) == 50000.0




def test_llm_drops_brackets_or_decorates_tokens():
    """Real LLMs often write tokens without [ ] or wrap them in quotes/backticks/bold."""
    _setup()
    sanitized, mapping, _ = pd.anonymize_prompt("I paid $1,250,000 for the house and $50,000 in fees.")
    ids = re.findall(r"CKKS_NUM_([0-9a-f]{8})_(\d+)", sanitized)
    rid = ids[0][0]
    a, b = f"CKKS_NUM_{rid}_2", f"CKKS_NUM_{rid}_1"   # house = _2, fees = _1
    assert pd.deanonymize_response(f"CKKS_SUM({a}, {b})", mapping) == "$1,300,000"
    assert pd.deanonymize_response(f"**CKKS_SUM(`{a}`, '{b}')**", mapping) == "**$1,300,000**"
    assert pd.deanonymize_response(f"CKKS_PCT([{a}], 18)", mapping) == "$225,000"
    assert pd.deanonymize_response(f"The house cost {a}.", mapping) == "The house cost $1,250,000."
    assert pd.deanonymize_response(f"The fees were [{b}].", mapping) == "The fees were $50,000."


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("PASS", name)
