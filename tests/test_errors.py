"""Tests for SensitiveDataError formatting."""

from __future__ import annotations

from spektralia.errors import SensitiveDataError


def test_str_with_labels_only():
    err = SensitiveDataError(reason="x", labels=("EMAIL", "AWS_KEY"))
    s = str(err)
    assert s.startswith("Blocked:")
    assert "rule(EMAIL,AWS_KEY)" in s


def test_str_with_categories_includes_classifier_part():
    err = SensitiveDataError(reason="x", categories=("PII", "CREDENTIALS"), confidence=0.87)
    s = str(err)
    assert "classifier(0.87, ['PII', 'CREDENTIALS'])" in s


def test_str_with_labels_and_categories_joined():
    err = SensitiveDataError(reason="x", labels=("EMAIL",), categories=("PII",), confidence=0.5)
    s = str(err)
    assert "rule(EMAIL)" in s
    assert "classifier(0.50, ['PII'])" in s
    assert " + " in s


def test_str_falls_back_to_reason_when_no_labels_or_categories():
    err = SensitiveDataError(reason="input_too_large")
    assert str(err) == "Blocked: input_too_large"


def test_repr_lists_fields_but_not_confidence_value_leak():
    err = SensitiveDataError(reason="r", labels=("EMAIL",), categories=("PII",))
    r = repr(err)
    assert "SensitiveDataError(" in r
    assert "reason='r'" in r
    assert "labels=('EMAIL',)" in r
    assert "categories=('PII',)" in r
