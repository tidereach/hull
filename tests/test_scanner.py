import spektralia.scanner as scanner_mod
from spektralia.scanner import (
    Detection,
    _dedupe,
    _remap_offset,
    _scan_idna_emails,
    scan,
)


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
        assert sorted_spans[i][0] >= sorted_spans[i - 1][1], f"Overlapping: {sorted_spans}"


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


# ---------------------------------------------------------------------------
# Detection.span and _remap_offset
# ---------------------------------------------------------------------------


def test_detection_span_property():
    d = Detection(label="EMAIL", start=3, end=9)
    assert d.span == (3, 9)


def test_remap_offset_in_range():
    assert _remap_offset(1, [10, 20, 30]) == 20


def test_remap_offset_out_of_range_uses_last():
    # offset beyond the map clamps to the final original index
    assert _remap_offset(99, [10, 20, 30]) == 30


def test_remap_offset_empty_map_returns_offset():
    assert _remap_offset(7, []) == 7


# ---------------------------------------------------------------------------
# _dedupe overlap resolution
# ---------------------------------------------------------------------------


def test_dedupe_longer_overlapping_span_replaces_shorter():
    # B starts inside A but extends further → B replaces A (result[-1] = det)
    a = Detection(label="A", start=0, end=5)
    b = Detection(label="B", start=2, end=10)
    result = _dedupe([a, b])
    assert result == [b]


def test_dedupe_always_emit_labels_preserved_under_overlap():
    secret = Detection(label="EMAIL", start=0, end=20)
    obfus = Detection(label="OBFUSCATION_CHAR", start=5, end=6)
    result = _dedupe([secret, obfus])
    labels = {d.label for d in result}
    assert "OBFUSCATION_CHAR" in labels  # never suppressed by overlap
    assert "EMAIL" in labels


# ---------------------------------------------------------------------------
# _scan_idna_emails non-matching and error branches
# ---------------------------------------------------------------------------


def test_idna_email_no_tld_not_matched():
    # 'münchen' IDNA-encodes fine but has no dot/TLD, so the EMAIL pattern
    # rejects it → no detection (the if-match-False branch).
    assert _scan_idna_emails("write to user@münchen now") == []


def test_idna_email_invalid_domain_swallowed():
    # A label longer than 63 chars makes idna encoding raise UnicodeError,
    # which must be caught and skipped (no crash, no detection).
    bad = "user@" + ("ü" * 64) + ".de"
    assert _scan_idna_emails(bad) == []


# ---------------------------------------------------------------------------
# REGEX_TIMEOUT sentinel in original / normalized / shadow scan passes
# ---------------------------------------------------------------------------


def test_regex_timeout_in_all_scan_passes(monkeypatch):
    from spektralia.normalize import normalize, whitespace_collapsed_shadow

    # Text that differs from BOTH its NFKC-normalized form (zero-width char)
    # and its whitespace-collapsed shadow (line-wrapped digits), so all three
    # scan passes execute.
    text = "ab​cd 4111\n1111 1111 1111"
    assert normalize(text).normalized != text
    assert whitespace_collapsed_shadow(text)[0] != text

    monkeypatch.setattr(scanner_mod, "match_pattern", lambda pat, t: [(-1, -1, "REGEX_TIMEOUT")])
    labels = {d.label for d in scan(text)}
    assert "REGEX_TIMEOUT" in labels
