import subprocess
import sys
from unittest.mock import patch

from spektralia.integrity import (
    compute_hook_token,
    compute_pattern_hash,
    get_integrity_report,
    get_or_create_hook_key,
    verify_installed,
)


def test_pattern_hash_is_deterministic():
    h1 = compute_pattern_hash()
    h2 = compute_pattern_hash()
    assert h1 == h2


def test_pattern_hash_is_64_hex():
    h = compute_pattern_hash()
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_integrity_report_returns_all_keys():
    report = get_integrity_report(None, "llama3.2:3b")
    assert "pattern_hash" in report
    assert "prompt_hash" in report
    assert "model_digest" in report


def test_pattern_hash_changes_with_pattern_change(monkeypatch):
    import spektralia.integrity as integrity_mod
    import spektralia.patterns as patterns_mod

    original = compute_pattern_hash()

    # Temporarily add a fake pattern
    from spektralia.patterns import Pattern

    new_patterns = [*patterns_mod.PATTERNS, Pattern(label="FAKE_TEST", regex=r"faketest123")]
    monkeypatch.setattr(patterns_mod, "PATTERNS", new_patterns)
    monkeypatch.setattr(integrity_mod, "PATTERNS", new_patterns)

    modified = compute_pattern_hash()
    assert original != modified


# ---------------------------------------------------------------------------
# verify_installed
# ---------------------------------------------------------------------------


class TestVerifyInstalled:
    def test_missing_lock_returns_problem(self, tmp_path):
        problems = verify_installed(tmp_path / "requirements.lock")
        assert any("not found" in p for p in problems)

    def test_matching_versions_returns_empty(self, tmp_path):
        # Build a minimal lock file matching a package we know is installed
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
        )
        # Pick the first pinned package
        pinned = [
            l.strip() for l in result.stdout.splitlines() if "==" in l and not l.startswith("-e")
        ]
        if not pinned:
            return  # nothing to check in this environment
        lock_path = tmp_path / "requirements.lock"
        lock_path.write_text(pinned[0] + " \\\n    --hash=sha256:fake\n")
        problems = verify_installed(lock_path)
        assert problems == []

    def test_wrong_version_returns_problem(self, tmp_path):
        lock_path = tmp_path / "requirements.lock"
        lock_path.write_text("httpx==0.0.0 \\\n    --hash=sha256:fake\n")
        problems = verify_installed(lock_path)
        assert any("httpx" in p for p in problems)

    def test_missing_package_returns_problem(self, tmp_path):
        lock_path = tmp_path / "requirements.lock"
        lock_path.write_text("nonexistent-pkg==1.2.3 \\\n    --hash=sha256:fake\n")
        problems = verify_installed(lock_path)
        assert any("nonexistent-pkg" in p for p in problems)


# ---------------------------------------------------------------------------
# hook identity (ASI-07)
# ---------------------------------------------------------------------------


class TestHookIdentity:
    def test_token_is_64_hex_when_key_available(self, monkeypatch):
        import spektralia.integrity as integrity_mod

        fake_key = b"\x01" * 32
        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: fake_key)
        token = compute_hook_token("test-session")
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_token_empty_when_keyring_unavailable(self, monkeypatch):
        import spektralia.integrity as integrity_mod

        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: b"")
        token = compute_hook_token("test-session")
        assert token == ""

    def test_different_sessions_produce_different_tokens(self, monkeypatch):
        import spektralia.integrity as integrity_mod

        fake_key = b"\x02" * 32
        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: fake_key)
        t1 = compute_hook_token("session-a")
        t2 = compute_hook_token("session-b")
        assert t1 != t2

    def test_get_or_create_returns_empty_on_keyring_error(self, monkeypatch):
        with patch("keyring.get_password", side_effect=Exception("no keyring")):
            key = get_or_create_hook_key()
        assert key == b""
