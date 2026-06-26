"""Contextual PII detection via a local Named-Entity-Recognition model (#44).

The regex + entropy scanner catches *structured* secrets (emails, keys, IDs) but
cannot see free-text PII — a person's name or a street address written in prose.
A local NER model closes that gap without sending anything to the cloud.

NER is gated behind ``Settings.ner_enabled`` (default ``False``) so existing
installs are unaffected until the operator opts in, and the heavy ``spaCy``
dependency is an optional ``ner`` extra. When the model or library is missing the
backend degrades to "no entities" rather than raising, keeping the gate's
fail-closed behaviour intact (regex/entropy/classifier still run).

The backend is a thin, injectable seam: ``SpacyNERBackend`` wraps a spaCy
pipeline, but any object exposing ``entities(text) -> list[(label, start, end)]``
works, which keeps the integration testable without downloading a model.
"""

from __future__ import annotations

from typing import Protocol

from .scanner import Detection

# Entity labels we surface, mapped to canonical Spektralia detection labels.
# Conservative on purpose: only high-signal entity types, to limit false
# positives on dates, ordinals, money, etc.
_SPACY_LABEL_MAP = {
    "PERSON": "PERSON",
    "PER": "PERSON",  # some non-English models use PER
    "GPE": "LOC",  # geopolitical entity (cities, countries)
    "LOC": "LOC",
    "ORG": "ORG",
}

# The detection labels NER can emit (used by tests and docs).
NER_LABELS = ("PERSON", "LOC", "ORG")


class NERBackend(Protocol):
    """Anything that can extract entity spans from text."""

    def entities(self, text: str) -> list[tuple[str, int, int]]:
        """Return ``(label, start_char, end_char)`` tuples in original-text coords."""
        ...


class SpacyNERBackend:
    """NER backend backed by a spaCy pipeline.

    ``nlp`` may be injected (for testing) to avoid loading a real model; when
    ``None`` the model named by ``model`` is lazily loaded on first use.
    """

    def __init__(self, model: str = "en_core_web_sm", nlp: object | None = None) -> None:
        self._model = model
        self._nlp = nlp

    def _load(self):
        if self._nlp is None:  # pragma: no cover - needs the `ner` extra + a downloaded model
            import spacy

            self._nlp = spacy.load(self._model)
        return self._nlp

    def entities(self, text: str) -> list[tuple[str, int, int]]:
        try:
            nlp = self._load()
        except BaseException:
            # spaCy or the model is unavailable — degrade to no entities.
            return []
        doc = nlp(text)
        out: list[tuple[str, int, int]] = []
        for ent in getattr(doc, "ents", []):
            label = _SPACY_LABEL_MAP.get(getattr(ent, "label_", ""))
            if label:
                out.append((label, ent.start_char, ent.end_char))
        return out


def scan_entities(text: str, backend: NERBackend) -> list[Detection]:
    """Run ``backend`` over ``text`` and return NER detections in original coords.

    Spans are clamped to the text bounds and zero-width/invalid spans dropped, so
    they flow through the same span-replacement sanitizer as regex hits.
    """
    if not text:
        return []
    detections: list[Detection] = []
    for label, start, end in backend.entities(text):
        if 0 <= start < end <= len(text):
            detections.append(Detection(label=label, start=start, end=end))
    return detections


def build_ner_backend(model: str = "en_core_web_sm") -> SpacyNERBackend:
    """Construct the default (spaCy) NER backend for the given model name."""
    return SpacyNERBackend(model=model)
