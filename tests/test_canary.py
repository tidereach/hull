import json

import spektralia.canary as canary_mod
from spektralia.canary import _CORPUS, _NER_CORPUS, _load_disk_corpus, run_canary, run_ner_canary
from spektralia.scanner import Detection, scan


def test_canary_passes_with_real_scanner():
    result = run_canary(scan)
    assert result.passed, f"Canary failures: {result.failures}"


def test_canary_detects_broken_scanner():
    def broken_scan(text):
        return []

    result = run_canary(broken_scan)
    assert not result.passed
    assert result.failures


def test_canary_corpus_has_positive_and_negative():
    positives = [c for c in _CORPUS if c.must_detect_regex]
    negatives = [c for c in _CORPUS if not c.must_detect_regex]
    assert positives, "No positive canary cases"
    assert negatives, "No negative canary cases"


# ---------- _load_disk_corpus ----------


def test_load_disk_corpus_missing_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(canary_mod, "_CORPUS_DIR", tmp_path / "nonexistent")
    assert _load_disk_corpus() == []


def test_load_disk_corpus_valid_file(monkeypatch, tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "case1.json").write_text(
        json.dumps({"text": "foo@bar.com", "expected_labels": ["EMAIL"], "must_detect_regex": True})
    )
    monkeypatch.setattr(canary_mod, "_CORPUS_DIR", corpus_dir)
    cases = _load_disk_corpus()
    assert len(cases) == 1
    assert cases[0].text == "foo@bar.com"
    assert cases[0].expected_labels == ["EMAIL"]
    assert cases[0].must_detect_regex is True


def test_load_disk_corpus_malformed_file_skipped(monkeypatch, tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "bad.json").write_text("{not valid json")
    (corpus_dir / "good.json").write_text(json.dumps({"text": "ok text", "expected_labels": []}))
    monkeypatch.setattr(canary_mod, "_CORPUS_DIR", corpus_dir)
    cases = _load_disk_corpus()
    assert len(cases) == 1
    assert cases[0].text == "ok text"


def test_load_disk_corpus_missing_key_skipped(monkeypatch, tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    (corpus_dir / "notext.json").write_text(json.dumps({"expected_labels": []}))
    monkeypatch.setattr(canary_mod, "_CORPUS_DIR", corpus_dir)
    assert _load_disk_corpus() == []


# ---------- run_ner_canary ----------


def _make_entity_fn(*labels):
    def entity_fn(text):
        return [Detection(label=lbl, start=0, end=1) for lbl in labels]

    return entity_fn


def test_run_ner_canary_passes():
    # Provide an entity_fn that always returns whatever each case expects
    def smart_fn(text):
        for case in _NER_CORPUS:
            if case.text in text and case.expected_labels:
                return [Detection(label=lbl, start=0, end=1) for lbl in case.expected_labels]
        return []

    result = run_ner_canary(smart_fn)
    assert result.passed, result.failures


def test_run_ner_canary_fails_on_missing_entity():
    result = run_ner_canary(_make_entity_fn())  # returns nothing
    assert not result.passed
    assert any("ner-canary: expected" in f for f in result.failures)


def test_run_ner_canary_fails_on_unexpected_entity():
    # Always returns a PERSON entity — trips on the false-positive cases
    result = run_ner_canary(_make_entity_fn("PERSON"))
    assert not result.passed
    assert any("unexpected" in f for f in result.failures)


def test_run_ner_canary_result_has_duration():
    result = run_ner_canary(_make_entity_fn())
    assert result.duration_seconds >= 0
