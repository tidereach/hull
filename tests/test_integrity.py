import subprocess
import sys
from unittest.mock import patch

import httpx
import pytest
import respx

import spektralia.integrity as integrity_mod
from spektralia.integrity import (
    compute_hook_identity,
    compute_hook_token,
    compute_pattern_hash,
    fetch_model_digest,
    get_integrity_report,
    get_or_create_ed25519_seed,
    get_or_create_hook_key,
    hook_public_key_hex,
    verify_hook_identity,
    verify_installed,
)


def _crypto_available() -> bool:
    return integrity_mod._ed25519_module() is not None


requires_crypto = pytest.mark.skipif(
    not _crypto_available(), reason="cryptography Ed25519 backend unavailable"
)


class _FakeKeyring:
    """In-memory keyring stand-in for deterministic key-store tests."""

    def __init__(self):
        self.store: dict = {}

    def get_password(self, service, name):
        return self.store.get((service, name))

    def set_password(self, service, name, value):
        self.store[(service, name)] = value


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

    def test_get_or_create_survives_base_exception(self, monkeypatch):
        # A broken Rust keyring backend can raise PanicException (BaseException,
        # not Exception). The hook must degrade to unauthenticated, not crash.
        with patch("keyring.get_password", side_effect=BaseException("pyo3 panic")):
            assert get_or_create_hook_key() == b""

    def test_control_exceptions_are_not_swallowed(self):
        # KeyboardInterrupt / SystemExit must propagate, never degrade to b"".
        for control in (KeyboardInterrupt, SystemExit):
            with patch("keyring.get_password", side_effect=control()):
                with pytest.raises(control):
                    get_or_create_hook_key()

    def test_reraise_if_control_helper(self):
        # Non-control exceptions pass through (no raise); control ones re-raise.
        assert integrity_mod._reraise_if_control(ValueError("x")) is None
        with pytest.raises(KeyboardInterrupt):
            integrity_mod._reraise_if_control(KeyboardInterrupt())
        with pytest.raises(SystemExit):
            integrity_mod._reraise_if_control(SystemExit())


# ---------------------------------------------------------------------------
# Ed25519 cryptographic hook identity (#45)
# ---------------------------------------------------------------------------


class TestEd25519Identity:
    def test_seed_empty_when_module_unavailable(self, monkeypatch):
        monkeypatch.setattr(integrity_mod, "_ed25519_module", lambda: None)
        assert get_or_create_ed25519_seed() == b""

    def test_seed_empty_on_keyring_base_exception(self, monkeypatch):
        if not _crypto_available():
            pytest.skip("cryptography unavailable")
        with patch("keyring.get_password", side_effect=BaseException("pyo3 panic")):
            assert get_or_create_ed25519_seed() == b""

    def test_public_key_empty_without_seed(self, monkeypatch):
        monkeypatch.setattr(integrity_mod, "get_or_create_ed25519_seed", lambda: b"")
        assert hook_public_key_hex() == ""

    @requires_crypto
    def test_seed_generated_and_persisted(self, monkeypatch):
        fake = _FakeKeyring()
        monkeypatch.setattr("keyring.get_password", fake.get_password)
        monkeypatch.setattr("keyring.set_password", fake.set_password)
        seed = get_or_create_ed25519_seed()
        assert len(seed) == 32
        # Second call reads the stored seed (hex round-trip)
        assert get_or_create_ed25519_seed() == seed

    @requires_crypto
    def test_public_key_is_64_hex(self, monkeypatch):
        fake = _FakeKeyring()
        monkeypatch.setattr("keyring.get_password", fake.get_password)
        monkeypatch.setattr("keyring.set_password", fake.set_password)
        pub = hook_public_key_hex()
        assert len(pub) == 64
        assert all(c in "0123456789abcdef" for c in pub)

    @requires_crypto
    def test_identity_ed25519_roundtrip(self, monkeypatch):
        fake = _FakeKeyring()
        monkeypatch.setattr("keyring.get_password", fake.get_password)
        monkeypatch.setattr("keyring.set_password", fake.set_password)
        identity = compute_hook_identity("session-x")
        assert identity["scheme"] == "ed25519"
        assert verify_hook_identity(identity) is True
        # Pinning the matching public key also verifies.
        assert verify_hook_identity(identity, trusted_pub_hex=identity["pub"]) is True

    @requires_crypto
    def test_identity_ed25519_tampered_nonce_fails(self, monkeypatch):
        fake = _FakeKeyring()
        monkeypatch.setattr("keyring.get_password", fake.get_password)
        monkeypatch.setattr("keyring.set_password", fake.set_password)
        identity = compute_hook_identity("session-x")
        identity["nonce"] = identity["nonce"] + "tampered"
        assert verify_hook_identity(identity) is False

    @requires_crypto
    def test_identity_ed25519_forged_pub_rejected(self, monkeypatch):
        # An attacker who swaps in their own keypair must not pass when the
        # verifier pins the trusted (install-time) public key.
        fake = _FakeKeyring()
        monkeypatch.setattr("keyring.get_password", fake.get_password)
        monkeypatch.setattr("keyring.set_password", fake.set_password)
        trusted_pub = hook_public_key_hex()

        ed25519 = integrity_mod._ed25519_module()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        attacker = ed25519.Ed25519PrivateKey.generate()
        forged = {
            "scheme": "ed25519",
            "nonce": "unknown:1",
            "sig": attacker.sign(b"unknown:1").hex(),
            "pub": attacker.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        }
        # Without pinning, the forged self-consistent proof would verify against
        # its own embedded pub — but pinning the trusted key rejects it.
        assert verify_hook_identity(forged, trusted_pub_hex=trusted_pub) is False

    def test_identity_hmac_fallback(self, monkeypatch):
        # No Ed25519 seed → HMAC tag.
        monkeypatch.setattr(integrity_mod, "get_or_create_ed25519_seed", lambda: b"")
        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: b"\x05" * 32)
        identity = compute_hook_identity("session-y")
        assert identity["scheme"] == "hmac"
        assert verify_hook_identity(identity) is True

    def test_identity_hmac_tampered_fails(self, monkeypatch):
        monkeypatch.setattr(integrity_mod, "get_or_create_ed25519_seed", lambda: b"")
        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: b"\x05" * 32)
        identity = compute_hook_identity("session-y")
        identity["sig"] = "00" * 32
        assert verify_hook_identity(identity) is False

    def test_identity_none_when_no_keys(self, monkeypatch):
        monkeypatch.setattr(integrity_mod, "get_or_create_ed25519_seed", lambda: b"")
        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: b"")
        identity = compute_hook_identity("session-z")
        assert identity["scheme"] == "none"
        assert identity["sig"] == ""
        assert verify_hook_identity(identity) is False

    def test_verify_unknown_scheme_is_false(self):
        assert verify_hook_identity({"scheme": "rsa", "nonce": "n", "sig": "x"}) is False

    def test_verify_hmac_without_key_is_false(self, monkeypatch):
        monkeypatch.setattr(integrity_mod, "get_or_create_hook_key", lambda: b"")
        assert verify_hook_identity({"scheme": "hmac", "nonce": "n", "sig": "x"}) is False

    def test_verify_ed25519_without_module_is_false(self, monkeypatch):
        monkeypatch.setattr(integrity_mod, "_ed25519_module", lambda: None)
        assert verify_hook_identity({"scheme": "ed25519", "nonce": "n", "sig": "x"}) is False

    @requires_crypto
    def test_verify_ed25519_without_pubkey_is_false(self, monkeypatch):
        # Ed25519 scheme but no trusted/derivable public key → cannot verify.
        monkeypatch.setattr(integrity_mod, "hook_public_key_hex", lambda: "")
        assert verify_hook_identity({"scheme": "ed25519", "nonce": "n", "sig": "x"}) is False
