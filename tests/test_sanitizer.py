import re
import pytest
from spektralia.sanitizer import sanitize, _restore
from spektralia.scanner import Detection


def _dets(*spans_and_labels):
    return [Detection(label=l, start=s, end=e) for l, s, e in spans_and_labels]


def test_token_replaces_span():
    text = "Email: alice@example.com is good"
    det = Detection(label="EMAIL", start=7, end=24)
    result = sanitize(text, [det])
    assert "alice@example.com" not in result.text
    assert "[REDACTED:EMAIL:" in result.text


def test_token_random_suffix():
    text = "a@b.com and c@d.com"
    dets = [
        Detection(label="EMAIL", start=0, end=7),
        Detection(label="EMAIL", start=12, end=19),
    ]
    result = sanitize(text, dets)
    tokens = re.findall(r"\[REDACTED:EMAIL:[0-9a-f]{6}\]", result.text)
    assert len(tokens) == 2
    # Suffixes must be unique
    suffixes = [t[-7:-1] for t in tokens]
    assert len(set(suffixes)) == 2, f"Suffixes not unique: {suffixes}"


def test_no_detection_returns_original():
    text = "hello world"
    result = sanitize(text, [])
    assert result.text == text
    assert result._token_map == {}


def test_token_map_stores_secret():
    from spektralia.memory_safety import Secret
    text = "key: AKIAIOSFODNN7EXAMPLE"
    det = Detection(label="AWS_KEY", start=5, end=24)
    result = sanitize(text, [det])
    assert result._token_map
    for token, secret in result._token_map.items():
        assert isinstance(secret, Secret)
        assert repr(secret) == "<Secret:AWS_KEY:redacted>"


def test_restore_roundtrip():
    text = "Email: alice@example.com"
    det = Detection(label="EMAIL", start=7, end=24)
    sanitized = sanitize(text, [det])
    restored = _restore(sanitized.text, sanitized, unsafe_restore_fields=["EMAIL"])
    assert "alice@example.com" in restored


def test_restore_removes_from_map():
    text = "Email: alice@example.com"
    det = Detection(label="EMAIL", start=7, end=24)
    sanitized = sanitize(text, [det])
    _restore(sanitized.text, sanitized, unsafe_restore_fields=["EMAIL"])
    # After restore, map should be empty
    assert sanitized._token_map == {}


def test_detection_has_no_value():
    text = "AKIAIOSFODNN7EXAMPLE"
    det = Detection(label="AWS_KEY", start=0, end=20)
    assert not hasattr(det, "value")
