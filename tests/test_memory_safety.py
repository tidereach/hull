import platform
import traceback

import pytest

from spektralia.memory_safety import Secret, disable_core_dumps


def test_repr_does_not_leak_value():
    s = Secret(b"sk_live_supersecretkey123", label="API_KEY")
    r = repr(s)
    assert "supersecretkey" not in r
    assert "sk_live" not in r
    assert "redacted" in r.lower()


def test_str_does_not_leak_value():
    s = Secret(b"sk_live_supersecretkey123", label="API_KEY")
    assert "supersecretkey" not in str(s)
    assert "sk_live" not in str(s)


def test_label_in_repr():
    s = Secret(b"somevalue", label="CREDIT_CARD")
    assert "CREDIT_CARD" in repr(s)


def test_wipe_zeroes_buffer():
    s = Secret(b"password123", label="PWD")
    s.wipe()
    assert all(b == 0 for b in s._buf)


def test_as_bytes_before_wipe():
    s = Secret(b"password123", label="PWD")
    assert s.as_bytes() == b"password123"


def test_as_str_before_wipe():
    s = Secret(b"hello", label="X")
    assert s.as_str() == "hello"


def test_wipe_idempotent():
    s = Secret(b"value", label="X")
    s.wipe()
    s.wipe()  # Should not raise


def test_secret_not_hashable():
    s = Secret(b"val", label="X")
    with pytest.raises(TypeError):
        hash(s)


def test_secret_equality():
    a = Secret(b"abc", label="X")
    b = Secret(b"abc", label="Y")
    assert a == b


def test_secret_inequality():
    a = Secret(b"abc", label="X")
    b = Secret(b"xyz", label="X")
    assert a != b


def test_secret_len():
    s = Secret(b"hello", label="X")
    assert len(s) == 5


def test_secret_in_exception_message_does_not_leak():
    value = b"very_secret_password_xyz"
    s = Secret(value, label="PWD")
    try:
        raise ValueError(f"error: {s}")
    except ValueError as exc:
        assert b"very_secret_password_xyz".decode() not in str(exc)
        assert b"very_secret_password_xyz".decode() not in traceback.format_exc()


def test_disable_core_dumps_no_crash():
    # Should not raise on any platform
    disable_core_dumps()


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
def test_pr_set_dumpable_executes_on_linux():
    # Just verify it runs without error on Linux
    disable_core_dumps()


def test_prctl_called_on_module_import(monkeypatch):
    """PR_SET_DUMPABLE=0 must be called when memory_safety is imported."""
    import ctypes as _ctypes
    import sys

    calls = []

    class FakeLibc:
        def prctl(self, *args):
            calls.append(args)
            return 0

    class FakeCDLL:
        def __init__(self, name, **kwargs):
            pass

        def __call__(self, name, **kwargs):
            return FakeLibc()

    # Remove the cached module so reload triggers the module-level call again
    mod_name = "spektralia.memory_safety"
    saved = sys.modules.pop(mod_name, None)
    try:
        monkeypatch.setattr(_ctypes, "CDLL", lambda name, **kw: FakeLibc())
        import sys as _sys

        import spektralia.memory_safety  # triggers module-level disable_core_dumps()

        if _sys.platform == "linux":
            assert any(
                args[0] == 4 and args[1] == 0 for args in calls
            ), f"Expected prctl(PR_SET_DUMPABLE=4, 0) call, got: {calls}"
    finally:
        if saved is not None:
            sys.modules[mod_name] = saved
        elif mod_name in sys.modules:
            del sys.modules[mod_name]
        # Re-import to restore module state
        import spektralia.memory_safety  # noqa: F401
