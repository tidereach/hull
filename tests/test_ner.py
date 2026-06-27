"""Tests for contextual PII / NER detection (#44).

The spaCy model is never downloaded in CI, so these tests inject fake/keyword
backends to exercise the mapping, span handling, gate integration, and canary
without the heavy dependency. A single opt-in test runs the real backend if a
model happens to be installed, and skips otherwise.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from spektralia.canary import run_ner_canary
from spektralia.config import Settings
from spektralia.gate import Gate
from spektralia.ner import (
    NER_LABELS,
    SpacyNERBackend,
    build_ner_backend,
    scan_entities,
)

MOCK_BASE = "http://127.0.0.1:11434"


class _FakeEnt:
    def __init__(self, label, start, end):
        self.label_ = label
        self.start_char = start
        self.end_char = end


class _FakeDoc:
    def __init__(self, ents):
        self.ents = ents


class _FakeNLP:
    """Stand-in spaCy pipeline: maps configured (label, substring) to entities."""

    def __init__(self, spans):
        # spans: list of (spacy_label, substring)
        self._spans = spans

    def __call__(self, text):
        ents = []
        for label, sub in self._spans:
            idx = text.find(sub)
            if idx >= 0:
                ents.append(_FakeEnt(label, idx, idx + len(sub)))
        return _FakeDoc(ents)


class KeywordNERBackend:
    """Backend that returns entity spans for known keywords (deterministic)."""

    def __init__(self, mapping):
        self._mapping = mapping  # {keyword: label}

    def entities(self, text):
        out = []
        for kw, label in self._mapping.items():
            idx = text.find(kw)
            if idx >= 0:
                out.append((label, idx, idx + len(kw)))
        return out


# ---------------------------------------------------------------------------
# SpacyNERBackend
# ---------------------------------------------------------------------------


class TestSpacyNERBackend:
    def test_maps_known_labels(self):
        nlp = _FakeNLP([("PERSON", "John Smith"), ("GPE", "Berlin"), ("ORG", "Acme")])
        be = SpacyNERBackend(nlp=nlp)
        ents = be.entities("John Smith from Acme visited Berlin")
        labels = {e[0] for e in ents}
        assert labels == {"PERSON", "LOC", "ORG"}  # GPE → LOC

    def test_drops_unmapped_labels(self):
        nlp = _FakeNLP([("DATE", "Monday"), ("MONEY", "five dollars")])
        be = SpacyNERBackend(nlp=nlp)
        assert be.entities("Monday costs five dollars") == []

    def test_per_label_maps_to_person(self):
        nlp = _FakeNLP([("PER", "Ola Nordmann")])
        be = SpacyNERBackend(nlp=nlp)
        assert be.entities("Ola Nordmann ringte") == [("PERSON", 0, 12)]

    def test_degrades_when_model_unavailable(self):
        # nlp=None and spaCy/model absent → no entities, no exception.
        be = SpacyNERBackend(model="nonexistent_model_xyz", nlp=None)
        assert be.entities("Some text with a Name") == []


# ---------------------------------------------------------------------------
# scan_entities
# ---------------------------------------------------------------------------


class TestScanEntities:
    def test_returns_detections(self):
        be = KeywordNERBackend({"Jane Doe": "PERSON"})
        dets = scan_entities("Contact Jane Doe please", be)
        assert len(dets) == 1
        d = dets[0]
        assert d.label == "PERSON"
        assert "Jane Doe" == "Contact Jane Doe please"[d.start : d.end]

    def test_empty_text(self):
        assert scan_entities("", KeywordNERBackend({"X": "PERSON"})) == []

    def test_invalid_spans_dropped(self):
        class Bad:
            def entities(self, text):
                return [("PERSON", 5, 5), ("LOC", -1, 3), ("ORG", 0, 999)]

        assert scan_entities("short", Bad()) == []

    def test_build_ner_backend_returns_spacy_backend(self):
        be = build_ner_backend("en_core_web_sm")
        assert isinstance(be, SpacyNERBackend)


# ---------------------------------------------------------------------------
# Gate integration
# ---------------------------------------------------------------------------


def _cr(sensitive, confidence, categories=None):
    cats = categories if categories is not None else ([] if not sensitive else ["PII"])
    return {
        "response": json.dumps(
            {"sensitive": sensitive, "confidence": confidence, "categories": cats}
        )
    }


def _gate(tmp_path, **kwargs):
    s = Settings(
        state_dir=tmp_path / "state",
        freeze_path=tmp_path / "freeze",
        ollama_url=MOCK_BASE,
        **kwargs,
    )
    return Gate(settings=s)


class TestGateNERIntegration:
    @pytest.mark.asyncio
    @respx.mock
    async def test_ner_name_blocks_when_classifier_safe(self, tmp_path):
        # Classifier says safe; NER must still produce a rule hit → block.
        respx.post(f"{MOCK_BASE}/api/generate").mock(
            side_effect=[
                httpx.Response(200, json=_cr(False, 0.01, [])),
                httpx.Response(200, json=_cr(False, 0.01, [])),
            ]
        )
        g = _gate(tmp_path, ner_enabled=True)
        g._ner_backend = KeywordNERBackend({"Jane Doe": "PERSON"})
        from spektralia.errors import SensitiveDataError

        with patch.object(g, "_get_client", return_value=httpx.Client(base_url=MOCK_BASE)):
            with pytest.raises(SensitiveDataError) as exc:
                await g.gate("Please email Jane Doe the notes")
        assert "PERSON" in str(exc.value)

    @pytest.mark.asyncio
    @respx.mock
    async def test_ner_disabled_lets_name_pass(self, tmp_path):
        respx.post(f"{MOCK_BASE}/api/generate").mock(
            side_effect=[
                httpx.Response(200, json=_cr(False, 0.01, [])),
                httpx.Response(200, json=_cr(False, 0.01, [])),
            ]
        )
        g = _gate(tmp_path, ner_enabled=False)
        # Even if a backend is present, ner_enabled=False must skip it.
        g._ner_backend = KeywordNERBackend({"Jane Doe": "PERSON"})
        with patch.object(g, "_get_client", return_value=httpx.Client(base_url=MOCK_BASE)):
            result = await g.gate("Please email Jane Doe the notes")
        assert not result.blocked
        assert all(d.label != "PERSON" for d in result.detections)

    @pytest.mark.asyncio
    @respx.mock
    async def test_ner_error_does_not_crash_gate(self, tmp_path):
        respx.post(f"{MOCK_BASE}/api/generate").mock(
            side_effect=[
                httpx.Response(200, json=_cr(False, 0.01, [])),
                httpx.Response(200, json=_cr(False, 0.01, [])),
            ]
        )

        class Boom:
            def entities(self, text):
                raise RuntimeError("backend exploded")

        g = _gate(tmp_path, ner_enabled=True)
        g._ner_backend = Boom()
        with patch.object(g, "_get_client", return_value=httpx.Client(base_url=MOCK_BASE)):
            result = await g.gate("hello world")
        assert not result.blocked

    def test_lazy_backend_built_once(self, tmp_path):
        g = _gate(tmp_path, ner_enabled=True, ner_model="en_core_web_sm")
        be1 = g._get_ner_backend()
        be2 = g._get_ner_backend()
        assert be1 is be2
        assert isinstance(be1, SpacyNERBackend)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestNERSettings:
    def test_ner_fields_default_off(self):
        s = Settings()
        assert s.ner_enabled is False
        assert s.ner_model == "en_core_web_sm"

    def test_ner_enabled_is_policy_affecting(self):
        a = Settings(ner_enabled=False)
        b = Settings(ner_enabled=True)
        assert a.config_hash() != b.config_hash()

    def test_ner_model_is_policy_affecting(self):
        a = Settings(ner_enabled=True, ner_model="en_core_web_sm")
        b = Settings(ner_enabled=True, ner_model="en_core_web_lg")
        assert a.config_hash() != b.config_hash()

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_NER_ENABLED", "1")
        monkeypatch.setenv("SPEKTRALIA_NER_MODEL", "xx_ent_wiki_sm")
        s = Settings.from_env()
        assert s.ner_enabled is True
        assert s.ner_model == "xx_ent_wiki_sm"


# ---------------------------------------------------------------------------
# NER canary corpus
# ---------------------------------------------------------------------------


class TestNERCanary:
    def test_canary_passes_with_correct_backend(self):
        backend = KeywordNERBackend(
            {"John Smith": "PERSON", "Berlin": "LOC", "Acme Corporation": "ORG"}
        )
        result = run_ner_canary(lambda t: scan_entities(t, backend))
        assert result.passed, result.failures

    def test_canary_fails_when_tp_missed(self):
        # Backend that detects nothing → true positives missed.
        empty = KeywordNERBackend({})
        result = run_ner_canary(lambda t: scan_entities(t, empty))
        assert not result.passed
        assert any("expected" in f for f in result.failures)

    def test_canary_fails_on_false_positive(self):
        # Backend that flags a benign-prose word as a person.
        noisy = KeywordNERBackend({"report": "PERSON", "meeting": "PERSON"})
        result = run_ner_canary(lambda t: scan_entities(t, noisy))
        assert not result.passed
        assert any("unexpected" in f for f in result.failures)


def test_ner_labels_constant():
    assert set(NER_LABELS) == {"PERSON", "LOC", "ORG"}


@pytest.mark.skipif(
    not build_ner_backend().entities("Barack Obama visited Paris"),
    reason="no spaCy model installed",
)
def test_real_spacy_backend_detects_entities():  # pragma: no cover - only with a model
    be = build_ner_backend()
    ents = be.entities("Barack Obama visited Paris last week")
    assert any(label == "PERSON" for label, _, _ in ents)
