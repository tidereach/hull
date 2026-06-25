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
                digest = m.get("digest", "")
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
    """
    try:
        import keyring  # type: ignore[import]

        stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_KEY)
        if stored:
            return bytes.fromhex(stored)
        key = _secrets.token_bytes(32)
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_KEY, key.hex())
        return key
    except Exception:
        return b""


def compute_hook_token(session_id: str | None = None) -> str:
    """HMAC-SHA256 over 'session_id:wall_ns' with the stored hook key.

    Returns empty string if the keyring key is unavailable — the absence of a
    token is itself auditable (hook replaced or keyring broken).
    """
    key = get_or_create_hook_key()
    if not key:
        return ""
    wall_ns = time.time_ns()
    msg = f"{session_id or 'unknown'}:{wall_ns}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
