"""
Tests for the optional BERT entity layer (stage 1). None of these need torch,
transformers or a model download.
Run from the project root:  python -m pytest tests/test_entity_engine.py -v
(or)                        python tests/test_entity_engine.py
"""
import os
import subprocess
import sys
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import gateway.pii_detector as pd
from gateway.pii_detector import BertEntityLayer


def _fake_ner(spans):
    """Returns a NER callable that reports `spans` ((word, label, score)) wherever the word occurs in the chunk."""
    def ner(text):
        out = []
        for word, label, score in spans:
            i = text.find(word)
            while i != -1:
                out.append({"entity_group": label, "score": score, "start": i, "end": i + len(word), "word": word})
                i = text.find(word, i + len(word))
        return out
    return ner


def _with_layer(layer, text):
    with mock.patch.object(pd, "bert_layer", layer):
        return pd.detect_pii(text)


def test_spacy_mode_never_imports_transformers():
    code = (
        "import sys, gateway.pii_detector as p\n"
        "p.detect_pii('Anil Kumar Verma works at Nexora Technologies in Hyderabad.')\n"
        "assert p.entity_engine_description() == 'regex + spaCy', p.entity_engine_description()\n"
        "assert 'transformers' not in sys.modules, 'transformers was imported'\n"
        "print('ok')\n"
    )
    env = dict(os.environ, ENTITY_ENGINE="spacy", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=ROOT)
    r = subprocess.run([sys.executable, "-c", code], env=env, cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip().endswith("ok"), r.stdout + r.stderr


def test_spacy_bert_without_transformers_falls_back():
    layer = BertEntityLayer(engine="spacy_bert")
    with mock.patch.dict(sys.modules, {"transformers": None}):  # makes `import transformers` fail
        assert layer.description() == "regex + spaCy (BERT requested but unavailable)"
        assert layer.detect("Anil Kumar Verma lives in Hyderabad") == []  # triggers the lazy load, must not raise
        assert layer.description() == "regex + spaCy (BERT requested but unavailable)"
        # detect_pii keeps working with regex + spaCy
        res = _with_layer(layer, "My PAN is ABCDE1234F")
    assert any(r.entity_type == "PAN_CARD" for r in res)


def test_default_engine_is_inactive_and_unchanged():
    layer = BertEntityLayer(engine="spacy", ner=_fake_ner([("Nexora", "ORG", 0.99)]))
    assert layer.detect("Nexora Technologies") == []
    assert layer.description() == "regex + spaCy"


def test_bert_spans_merged_and_filtered():
    text = "Nexora Technologies hired Priya in Pune and Misc Thing."
    ner = _fake_ner([("Nexora Technologies", "ORG", 0.95), ("Priya", "PER", 0.50),
                     ("Pune", "LOC", 0.90), ("Misc Thing", "MISC", 0.99)])
    layer = BertEntityLayer(engine="spacy_bert", min_score=0.80, entity_types="PER,ORG,LOC", ner=ner)
    assert layer.description() == "regex + spaCy + BERT (dslim/bert-base-NER)"
    got = {(r.entity_type, text[r.start:r.end]) for r in layer.detect(text)}
    assert ("ORGANIZATION", "Nexora Technologies") in got      # mapped and kept
    assert ("LOCATION", "Pune") in got                         # mapped and kept
    assert not any(t == "Priya" for _, t in got)               # below BERT_MIN_SCORE -> dropped
    assert not any(t == "Misc Thing" for _, t in got)          # unmapped label -> dropped
    # disabled entity types are dropped
    only_per = BertEntityLayer(engine="spacy_bert", entity_types="PER", ner=ner)
    assert only_per.detect(text) == []
    # and the merged spans reach detect_pii
    res = _with_layer(layer, text)
    assert ("ORGANIZATION", "Nexora Technologies") in {(r.entity_type, text[r.start:r.end]) for r in res}


def test_overlap_with_regex_resolves_like_other_recognizers():
    text = "My PAN is ABCDE1234F today"
    # BERT outscores the regex span (0.90): BERT wins, same greedy rule as any other recognizer.
    hi = BertEntityLayer(engine="spacy_bert", ner=_fake_ner([("ABCDE1234F", "PER", 0.97)]))
    res = _with_layer(hi, text)
    assert [r.entity_type for r in res if text[r.start:r.end] == "ABCDE1234F"] == ["PERSON"]
    # BERT scores below the regex span: the regex PAN_CARD span wins and BERT's is discarded.
    lo = BertEntityLayer(engine="spacy_bert", ner=_fake_ner([("ABCDE1234F", "PER", 0.85)]))
    res = _with_layer(lo, text)
    assert [r.entity_type for r in res if text[r.start:r.end] == "ABCDE1234F"] == ["PAN_CARD"]


def test_offsets_stay_correct_across_chunks():
    filler = ("The quarterly report was reviewed in detail by the team. " * 60)  # ~3400 chars, > 3 chunks
    text = filler + "Then Anil Kumar Verma signed. " + filler + "Finally Anil Kumar Verma left.\n" + filler
    assert len(text) > 3 * pd.BERT_CHUNK_CHARS
    chunks = list(BertEntityLayer._chunks(text))
    assert len(chunks) > 3 and "".join(c for _, c in chunks) == text
    assert all(text[o:o + len(c)] == c for o, c in chunks)
    layer = BertEntityLayer(engine="spacy_bert", ner=_fake_ner([("Anil Kumar Verma", "PER", 0.95)]))
    res = layer.detect(text)
    assert len(res) == 2
    assert all(text[r.start:r.end] == "Anil Kumar Verma" and r.entity_type == "PERSON" for r in res)
    assert [r.start for r in res] == [text.find("Anil Kumar Verma"), text.rfind("Anil Kumar Verma")]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("PASS", name)
