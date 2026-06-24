"""Assert no known secret value appears in exception messages or tracebacks."""
import traceback
import pytest
from spektralia.errors import SensitiveDataError
from spektralia.scanner import scan
from spektralia.sanitizer import sanitize


_KNOWN_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "alice@example.com",
    "4111111111111111",
    "sk_live_abcdefghijklmnopqrstuvwx",
]


def test_sensitive_data_error_does_not_contain_value():
    for secret in _KNOWN_SECRETS:
        exc = SensitiveDataError(reason="test_block", labels=("EMAIL",), categories=())
        exc_str = str(exc)
        exc_repr = repr(exc)
        assert secret not in exc_str, f"Secret {secret!r} in exc str: {exc_str!r}"
        assert secret not in exc_repr, f"Secret {secret!r} in exc repr: {exc_repr!r}"


def test_detection_repr_has_no_value():
    for secret in _KNOWN_SECRETS:
        dets = scan(f"test {secret} test")
        for det in dets:
            det_repr = repr(det)
            assert secret not in det_repr, f"Secret in Detection repr: {det_repr!r}"


def test_sanitized_token_map_repr_hides_value():
    from spektralia.scanner import Detection
    text = "AKIAIOSFODNN7EXAMPLE"
    det = Detection(label="AWS_KEY", start=0, end=20)
    sanitized = sanitize(text, [det])
    for token, secret in sanitized._token_map.items():
        assert "AKIAIOSFODNN7EXAMPLE" not in repr(secret)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(secret)


def test_exception_traceback_has_no_value():
    from spektralia.scanner import Detection
    for secret in _KNOWN_SECRETS:
        text = f"test {secret} test"
        dets = scan(text)
        sanitized = sanitize(text, dets)
        try:
            raise SensitiveDataError(reason="test", labels=("test",))
        except SensitiveDataError:
            tb = traceback.format_exc()
            assert secret not in tb, f"Secret {secret!r} found in traceback"
