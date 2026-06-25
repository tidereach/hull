import subprocess
import sys
from unittest.mock import patch

import httpx
import respx

from spektralia.integrity import (
    compute_hook_token,
    compute_pattern_hash,
    fetch_model_digest,
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
# fetch_model_digest
# ---------------------------------------------------------------------------


class TestFetchModelDigest:
    _BASE = "http://127.0.0.1:11434"

    @respx.mock
    def test_exact_name_match(self):
        respx.get(f"{self._BASE}/api/tags").mock(
            return_value=httpx.Response(
                200, json={"models": [{"name": "llama3.1:8b", "digest": "sha256:abc"}]}
            )
        )
        client = httpx.Client(base_url=self._BASE)
        assert fetch_model_digest(client, "llama3.1:8b") == "sha256:abc"

    @respx.mock
    def test_prefix_match(self):
        respx.get(f"{self._BASE}/api/tags").mock(
            return_value=httpx.Response(
                200, json={"models": [{"name": "llama3.1:latest", "digest": "sha256:def"}]}
            )
        )
        client = httpx.Client(base_url=self._BASE)
        # Requested "llama3.1:8b" — prefix "llama3.1" matches the installed tag
        assert fetch_model_digest(client, "llama3.1:8b") == "sha256:def"

    @respx.mock
    def test_model_not_found_returns_empty(self):
        respx.get(f"{self._BASE}/api/tags").mock(
            return_value=httpx.Response(200, json={"models": [{"name": "other:1b"}]})
        )
        client = httpx.Client(base_url=self._BASE)
        assert fetch_model_digest(client, "llama3.1:8b") == ""

    @respx.mock
    def test_request_error_returns_empty(self):
        respx.get(f"{self._BASE}/api/tags").mock(side_effect=httpx.ConnectError("refused"))
        client = httpx.Client(base_url=self._BASE)
        assert fetch_model_digest(client, "llama3.1:8b") == ""


# ---------------------------------------------------------------------------
# verify_installed
# ---------------------------------------------------------------------------


class TestVerifyInstalled:
    def test_missing_lock_returns_problem(self, tmp_path):
        problems = verify_installed(tmp_path / "requirements.lock")
        assert any("not found" in p for p in problems)

    def test_pip_freeze_failure_returns_problem(self, tmp_path, monkeypatch):
        lock_path = tmp_path / "requirements.lock"
        lock_path.write_text("httpx==0.27.0\n")

        def boom(*a, **k):
            raise subprocess.SubprocessError("pip exploded")

        monkeypatch.setattr(subprocess, "run", boom)
        problems = verify_installed(lock_path)
        assert any("pip freeze failed" in p for p in problems)

    def test_non_version_lock_lines_skipped(self, tmp_path):
        """Comment, blank, continuation, and bare-name lines are skipped, not errors."""
        lock_path = tmp_path / "requirements.lock"
        lock_path.write_text(
            "# a comment\n"
            "\n"
            "--hash=sha256:deadbeef\n"
            "via something\n"
            "bare-name-no-version\n"
        )
        # No "==" lines at all → nothing to compare → no problems.
        assert verify_installed(lock_path) == []

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

    def test_get_or_create_generates_and_stores_new_key(self):
        """With no stored key, a 32-byte key is generated and persisted to keyring."""
        store: dict = {}

        def fake_get(service, name):
            return store.get((service, name))

        def fake_set(service, name, value):
            store[(service, name)] = value

        with (
            patch("keyring.get_password", side_effect=fake_get),
            patch("keyring.set_password", side_effect=fake_set),
        ):
            key = get_or_create_hook_key()
            assert len(key) == 32
            # Second call returns the same stored key (hex round-trip)
            assert get_or_create_hook_key() == key

    def test_get_or_create_reads_existing_key(self):
        existing = (b"\x07" * 32).hex()
        with patch("keyring.get_password", return_value=existing):
            key = get_or_create_hook_key()
        assert key == b"\x07" * 32
