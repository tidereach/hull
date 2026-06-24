import pytest
from spektralia.scanner import scan, Detection


def test_email_detected():
    dets = scan("Send email to alice@example.com please")
    labels = {d.label for d in dets}
    assert "EMAIL" in labels


def test_overlapping_span_longer_wins():
    # Two patterns might overlap; deduplication keeps the longer span
    dets = scan("AKIAIOSFODNN7EXAMPLE and more")
    labels = {d.label for d in dets}
    assert "AWS_KEY" in labels
    # No overlapping duplicates
    spans = [(d.start, d.end) for d in dets]
    # All spans are non-overlapping
    sorted_spans = sorted(spans)
    for i in range(1, len(sorted_spans)):
        assert sorted_spans[i][0] >= sorted_spans[i-1][1], f"Overlapping: {sorted_spans}"


def test_empty_input():
    assert scan("") == []


def test_obfuscation_char_detected():
    # Zero-width space in the middle of an email
    text = "alice​@example.com"
    dets = scan(text)
    labels = {d.label for d in dets}
    assert "OBFUSCATION_CHAR" in labels


def test_credit_card_across_lines():
    # Whitespace-collapsed shadow catches line-wrapped card numbers
    text = "4111\n1111 1111 1111"
    dets = scan(text)
    labels = {d.label for d in dets}
    assert "CREDIT_CARD" in labels


def test_no_false_positives_on_lorem():
    text = "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod"
    dets = scan(text)
    real = [d for d in dets if d.label not in ("OBFUSCATION_CHAR",)]
    assert real == []


def test_detection_has_no_value_field():
    dets = scan("alice@example.com")
    assert dets
    det = dets[0]
    # Detection only has label, start, end — no 'value' attribute
    assert not hasattr(det, "value")
    assert hasattr(det, "label")
    assert hasattr(det, "start")
    assert hasattr(det, "end")


def test_idn_email_punycode_already_ascii():
    # Punycode form is valid ASCII — EMAIL regex must catch it directly
    dets = scan("alice@xn--mnchen-3ya.de")
    labels = {d.label for d in dets}
    assert "EMAIL" in labels


def test_idn_email_unicode_domain_detected():
    # Unicode domain (ü not a homoglyph) requires IDNA shadow to detect
    dets = scan("alice@münchen.de")
    labels = {d.label for d in dets}
    assert "EMAIL" in labels
