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
    payload = {"text": sanitized.text}
    restored = _restore(payload, sanitized, unsafe_restore_paths=["$.text"])
    assert "alice@example.com" in restored["text"]


def test_restore_removes_from_map():
    text = "Email: alice@example.com"
    det = Detection(label="EMAIL", start=7, end=24)
    sanitized = sanitize(text, [det])
    payload = {"text": sanitized.text}
    _restore(payload, sanitized, unsafe_restore_paths=["$.text"])
    # After restore, map should be empty
    assert sanitized._token_map == {}


def test_detection_has_no_value():
    text = "AKIAIOSFODNN7EXAMPLE"
    det = Detection(label="AWS_KEY", start=0, end=20)
    assert not hasattr(det, "value")


def test_restore_not_in_public_api():
    import spektralia
    assert not hasattr(spektralia, "_restore"), "_restore must not be in public __init__"
    assert not hasattr(spektralia, "restore"), "restore must not be in public __init__"


def test_restore_jsonpath_scoped():
    """Token at $.user.email restores; identical token at $.body does not."""
    from spektralia.sanitizer import sanitize, _restore
    from spektralia.memory_safety import Secret
    from spektralia.sanitizer import Sanitized

    token = "[REDACTED:EMAIL:abcdef]"
    token2 = "[REDACTED:EMAIL:aabbcc]"

    s3 = Sanitized(
        text="ignored",
        _token_map={
            token: Secret(b"alice@example.com", label="EMAIL"),
            token2: Secret(b"alice@example.com", label="EMAIL"),
        },
    )
    payload2 = {
        "user": {"email": f"send to {token}"},
        "body": f"message mentioning {token2}",
    }
    result = _restore(payload2, s3, unsafe_restore_paths=["$.user.email"])
    assert "alice@example.com" in result["user"]["email"]
    assert token2 in result["body"]  # body token NOT restored
    assert token not in s3._token_map  # consumed
    assert token2 in s3._token_map    # not consumed


def test_restore_flat_string_with_dollar_path():
    """Flat string + '$' path restores all tokens."""
    text = "Email: alice@example.com"
    det = Detection(label="EMAIL", start=7, end=24)
    sanitized = sanitize(text, [det])
    restored = _restore(sanitized.text, sanitized, unsafe_restore_paths=["$"])
    assert "alice@example.com" in restored


def test_restore_flat_string_no_dollar_path():
    """Flat string + path that isn't '$' restores nothing."""
    from spektralia.memory_safety import Secret
    from spektralia.sanitizer import Sanitized

    token = "[REDACTED:EMAIL:112233]"
    s = Sanitized(
        text=f"send to {token}",
        _token_map={token: Secret(b"alice@example.com", label="EMAIL")},
    )
    restored = _restore(s.text, s, unsafe_restore_paths=["$.email"])
    assert token in restored  # NOT restored
    assert token in s._token_map  # still in map


def test_restore_list_wildcard():
    """$.items[*] restores all items in a list."""
    from spektralia.memory_safety import Secret
    from spektralia.sanitizer import Sanitized

    token1 = "[REDACTED:EMAIL:111111]"
    token2 = "[REDACTED:EMAIL:222222]"
    s = Sanitized(
        text="ignored",
        _token_map={
            token1: Secret(b"alice@example.com", label="EMAIL"),
            token2: Secret(b"bob@example.com", label="EMAIL"),
        },
    )
    payload = {"items": [token1, token2]}
    result = _restore(payload, s, unsafe_restore_paths=["$.items[*]"])
    assert result["items"][0] == "alice@example.com"
    assert result["items"][1] == "bob@example.com"
    assert token1 not in s._token_map
    assert token2 not in s._token_map


def test_restore_list_index():
    """$[0] restores only the first list element."""
    from spektralia.memory_safety import Secret
    from spektralia.sanitizer import Sanitized

    token1 = "[REDACTED:EMAIL:333333]"
    token2 = "[REDACTED:EMAIL:444444]"
    s = Sanitized(
        text="ignored",
        _token_map={
            token1: Secret(b"alice@example.com", label="EMAIL"),
            token2: Secret(b"bob@example.com", label="EMAIL"),
        },
    )
    payload = [token1, token2]
    result = _restore(payload, s, unsafe_restore_paths=["$[0]"])
    assert result[0] == "alice@example.com"
    assert result[1] == token2  # NOT restored
    assert token1 not in s._token_map
    assert token2 in s._token_map
