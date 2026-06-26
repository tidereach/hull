"""Tests for model-output / assistant-turn gating (#47)."""

from __future__ import annotations

import spektralia.output_gate as output_gate_mod
from spektralia.config import Settings
from spektralia.output_gate import OutputScanResult, scan_output


class _KeywordNER:
    def __init__(self, mapping):
        self._mapping = mapping

    def entities(self, text):
        out = []
        for kw, label in self._mapping.items():
            idx = text.find(kw)
            if idx >= 0:
                out.append((label, idx, idx + len(kw)))
        return out


class TestScanOutput:
    def test_clean_output_not_flagged(self):
        r = scan_output("The build finished successfully.", Settings())
        assert isinstance(r, OutputScanResult)
        assert r.flagged is False
        assert r.labels == []

    def test_empty_output_not_flagged(self):
        assert scan_output("", Settings()).flagged is False

    def test_email_in_output_flagged(self):
        r = scan_output("Sure — reach me at alice@example.com.", Settings())
        assert r.flagged is True
        assert "EMAIL" in r.labels
        assert "output rule(" in r.reason

    def test_credential_in_output_flagged(self):
        r = scan_output("The key is AKIAIOSFODNN7EXAMPLE for AWS.", Settings())
        assert r.flagged is True
        assert "AWS_KEY" in r.labels

    def test_reason_never_contains_value(self):
        secret = "alice@example.com"
        r = scan_output(f"Contact {secret} please", Settings())
        assert secret not in r.reason

    def test_ner_entities_flagged_when_enabled(self, monkeypatch):
        monkeypatch.setattr(
            output_gate_mod, "build_ner_backend", lambda model: _KeywordNER({"Jane Doe": "PERSON"})
        )
        r = scan_output("Thanks Jane Doe, sending now.", Settings(ner_enabled=True))
        assert r.flagged is True
        assert "PERSON" in r.labels

    def test_ner_skipped_when_disabled(self, monkeypatch):
        called = {"n": 0}

        def _spy(model):
            called["n"] += 1
            return _KeywordNER({"Jane Doe": "PERSON"})

        monkeypatch.setattr(output_gate_mod, "build_ner_backend", _spy)
        r = scan_output("Thanks Jane Doe, sending now.", Settings(ner_enabled=False))
        assert r.flagged is False
        assert called["n"] == 0

    def test_ner_error_does_not_crash(self, monkeypatch):
        class Boom:
            def entities(self, text):
                raise RuntimeError("nope")

        monkeypatch.setattr(output_gate_mod, "build_ner_backend", lambda model: Boom())
        # Clean text + failing NER → still returns cleanly (not flagged).
        r = scan_output("nothing sensitive here", Settings(ner_enabled=True))
        assert r.flagged is False


class TestOutputGateSettings:
    def test_defaults_off(self):
        s = Settings()
        assert s.gate_outputs is False
        assert s.gate_outputs_mode == "warn"

    def test_not_policy_affecting(self):
        a = Settings(gate_outputs=False)
        b = Settings(gate_outputs=True, gate_outputs_mode="block")
        assert a.config_hash() == b.config_hash()

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS", "1")
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS_MODE", "block")
        s = Settings.from_env()
        assert s.gate_outputs is True
        assert s.gate_outputs_mode == "block"
