from __future__ import annotations

import hashlib
import hmac
import json
import secrets as _secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx

from .classifier import PROMPT_HASH
from .patterns import PATTERNS

_KEYRING_SERVICE = "spektralia"
_KEYRING_KEY = "hook_identity_key"
_KEYRING_ED25519_KEY = "hook_ed25519_seed"


def _reraise_if_control(exc: BaseException) -> None:
    """Re-raise interpreter-control exceptions so they are never swallowed.

    The hook-identity helpers below catch ``BaseException`` on purpose: a broken
    Rust-backed dependency (keyring / cryptography) can raise
    ``pyo3_runtime.PanicException``, which is a ``BaseException`` subclass, *not*
    an ``Exception`` — so ``except Exception`` would let it crash the hook. We must
    still let ``KeyboardInterrupt`` / ``SystemExit`` / ``GeneratorExit`` propagate;
    this guard, called first in each handler, ensures that.
    """
    if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
        raise exc


def compute_pattern_hash() -> str:
    """SHA-256 of sorted pattern table (label, regex, validator name, priority)."""
    table = []
    for p in sorted(PATTERNS, key=lambda x: x.label):
        table.append(
            {
                "label": p.label,
                "regex": p.regex,
                "validator": p.validator.__qualname__ if p.validator else None,
                "priority": p.priority,
            }
        )
    serialized = json.dumps(table, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def fetch_model_digest(client: httpx.Client, model_name: str) -> str:
    """Fetch model digest from Ollama /api/tags."""
    try:
        resp = client.get("/api/tags")
        resp.raise_for_status()
        for m in resp.json().get("models", []):
            if m.get("name") == model_name or m.get("name", "").startswith(
                model_name.split(":")[0]
            ):
                digest = str(m.get("digest", ""))
                return digest
    except Exception:
        pass
    return ""


def verify_installed(lock_path: Path) -> list[str]:
    """Compare installed packages against requirements.lock expected versions.

    Returns list of problems (empty = OK).
    """
    if not lock_path.exists():
        return [f"requirements.lock not found at {lock_path}"]

    # Get currently installed packages
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
    except Exception as e:
        return [f"pip freeze failed: {e}"]

    def _normalize(name: str) -> str:
        # PEP 508: -, _, and . are equivalent; names are case-insensitive
        import re

        return re.sub(r"[-_.]+", "-", name).lower()

    installed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if "==" in line and not line.startswith("-e"):
            pkg, ver = line.split("==", 1)
            installed[_normalize(pkg)] = ver.strip()

    # Parse lock file for expected package==version entries
    problems: list[str] = []
    for line in lock_path.read_text().splitlines():
        line = line.strip().rstrip("\\").strip()
        if not line or line.startswith("#") or line.startswith("-") or line.startswith("via"):
            continue
        if "==" in line:
            pkg_ver = line.split()[0]
            pkg, expected_ver = pkg_ver.split("==", 1)
            pkg_key = _normalize(pkg)
            if pkg_key not in installed:
                problems.append(f"{pkg}=={expected_ver}: not installed")
            elif installed[pkg_key] != expected_ver:
                problems.append(f"{pkg}: installed {installed[pkg_key]}, expected {expected_ver}")

    return problems


def get_integrity_report(client: httpx.Client | None, model_name: str) -> dict[str, str]:
    """Return all integrity hashes for logging and verify-integrity command."""
    pattern_hash = compute_pattern_hash()
    prompt_hash = PROMPT_HASH
    model_digest = fetch_model_digest(client, model_name) if client else ""
    return {
        "pattern_hash": pattern_hash,
        "prompt_hash": prompt_hash,
        "model_digest": model_digest,
    }


def get_or_create_hook_key() -> bytes:
    """Return the HMAC key for hook identity, generating and storing one on first call.

    Stored in the system keyring under service='spektralia'. Returns empty bytes
    if keyring is unavailable — callers treat that as unauthenticated.

    Catches ``BaseException`` rather than ``Exception``: some broken keyring
    backends raise ``pyo3_runtime.PanicException`` (a ``BaseException`` subclass)
    from their Rust bindings, which must degrade to "unauthenticated" rather than
    crashing the hook.
    """
    try:
        import keyring

        stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_KEY)
        if stored:
            return bytes.fromhex(stored)
        key = _secrets.token_bytes(32)
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_KEY, key.hex())
        return key
    except BaseException as exc:
        _reraise_if_control(exc)
        return b""


def compute_hook_token(session_id: str | None = None) -> str:
    """HMAC-SHA256 over 'session_id:wall_ns' with the stored hook key.

    Returns empty string if the keyring key is unavailable — the absence of a
    token is itself auditable (hook replaced or keyring broken).

    Retained for backward compatibility; new callers should prefer
    :func:`compute_hook_identity`, which prefers Ed25519 signatures.
    """
    key = get_or_create_hook_key()
    if not key:
        return ""
    wall_ns = time.time_ns()
    msg = f"{session_id or 'unknown'}:{wall_ns}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Ed25519 cryptographic hook identity (#45)
#
# The HMAC token above makes hook substitution auditable after the fact but
# cannot prove identity to a third party without sharing the secret. An Ed25519
# key pair lets the hook sign a per-call nonce; a verifier holding only the
# public key can confirm authenticity without keyring access. HMAC remains the
# fallback when ``cryptography`` or the keyring is unavailable.
# ---------------------------------------------------------------------------


def _ed25519_module():
    """Return the cryptography Ed25519 module, or ``None`` if unavailable.

    Catches ``BaseException`` because a broken ``cryptography`` install can raise
    ``pyo3_runtime.PanicException`` (not ``ImportError``) when its Rust bindings
    fail to load.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        return ed25519
    except BaseException as exc:  # pragma: no cover - broken/absent cryptography install
        _reraise_if_control(exc)
        return None


def get_or_create_ed25519_seed() -> bytes:
    """Return the raw 32-byte Ed25519 private seed, generating one on first call.

    Stored hex-encoded in the system keyring. Returns empty bytes if either
    ``cryptography`` or the keyring is unavailable, so callers fall back to HMAC.
    """
    ed25519 = _ed25519_module()
    if ed25519 is None:
        return b""
    try:
        import keyring
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_ED25519_KEY)
        if stored:
            return bytes.fromhex(stored)
        priv = ed25519.Ed25519PrivateKey.generate()
        seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_ED25519_KEY, seed.hex())
        return seed  # type: ignore[return-value]
    except BaseException as exc:
        _reraise_if_control(exc)
        return b""


def hook_public_key_hex() -> str:
    """Return the hex-encoded Ed25519 public key, or "" if unavailable.

    A verifier can pin this value (e.g. via ``audit-verify --pubkey``) to check
    hook signatures without keyring access.
    """
    seed = get_or_create_ed25519_seed()
    ed25519 = _ed25519_module()
    if not seed or ed25519 is None:
        return ""
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return pub.hex()  # type: ignore[return-value]
    except BaseException as exc:  # pragma: no cover - cryptography runtime failure
        _reraise_if_control(exc)
        return ""


def compute_hook_identity(session_id: str | None = None) -> dict[str, str]:
    """Build a per-call identity proof for a hook invocation.

    Returns a dict with at least ``scheme`` and ``nonce``. Prefers an Ed25519
    signature (``scheme="ed25519"`` with ``sig`` and ``pub``); falls back to an
    HMAC tag (``scheme="hmac"`` with ``sig``); finally ``scheme="none"`` with an
    empty signature when no key material is reachable. The absence of a signature
    is itself auditable.
    """
    wall_ns = time.time_ns()
    nonce = f"{session_id or 'unknown'}:{wall_ns}"

    seed = get_or_create_ed25519_seed()
    ed25519 = _ed25519_module()
    if seed and ed25519 is not None:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            sig = priv.sign(nonce.encode()).hex()
            pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            return {"scheme": "ed25519", "nonce": nonce, "sig": sig, "pub": pub}
        except BaseException as exc:  # pragma: no cover - cryptography runtime failure
            _reraise_if_control(exc)

    key = get_or_create_hook_key()
    if key:
        sig = hmac.new(key, nonce.encode(), hashlib.sha256).hexdigest()
        return {"scheme": "hmac", "nonce": nonce, "sig": sig}

    return {"scheme": "none", "nonce": nonce, "sig": ""}


def verify_hook_identity(identity: dict, *, trusted_pub_hex: str | None = None) -> bool:
    """Verify an identity proof produced by :func:`compute_hook_identity`.

    For Ed25519 proofs the signature is checked against ``trusted_pub_hex`` when
    supplied, otherwise against the locally stored key's public half — so a
    forged ``pub`` embedded in the proof cannot pass. HMAC proofs are checked by
    recomputing the tag with the stored key. Returns ``False`` for unsigned
    (``scheme="none"``) proofs, unknown schemes, or any verification error.
    """
    scheme = identity.get("scheme")
    nonce = str(identity.get("nonce", ""))
    sig = str(identity.get("sig", ""))

    if scheme == "ed25519":
        ed25519 = _ed25519_module()
        if ed25519 is None:
            return False
        pub_hex = trusted_pub_hex or hook_public_key_hex()
        if not pub_hex:
            return False
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(bytes.fromhex(sig), nonce.encode())
            return True
        except BaseException as exc:
            _reraise_if_control(exc)
            return False

    if scheme == "hmac":
        key = get_or_create_hook_key()
        if not key:
            return False
        expected = hmac.new(key, nonce.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    return False
