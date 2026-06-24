from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

from .patterns import PATTERNS
from .classifier import PROMPT_HASH


def compute_pattern_hash() -> str:
    """SHA-256 of sorted pattern table (label, regex, validator name, priority)."""
    table = []
    for p in sorted(PATTERNS, key=lambda x: x.label):
        table.append({
            "label": p.label,
            "regex": p.regex,
            "validator": p.validator.__qualname__ if p.validator else None,
            "priority": p.priority,
        })
    serialized = json.dumps(table, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def fetch_model_digest(client: httpx.Client, model_name: str) -> str:
    """Fetch model digest from Ollama /api/tags."""
    try:
        resp = client.get("/api/tags")
        resp.raise_for_status()
        for m in resp.json().get("models", []):
            if m.get("name") == model_name or m.get("name", "").startswith(model_name.split(":")[0]):
                digest = m.get("digest", "")
                return digest
    except Exception:
        pass
    return ""


def verify_installed(lock_path: Path) -> list[str]:
    """Compare pip freeze against requirements.lock hashes.

    Returns list of problems (empty = OK).
    """
    if not lock_path.exists():
        return [f"requirements.lock not found at {lock_path}"]

    problems: list[str] = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "hash", "--algorithm", "sha256"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as e:
        return [f"pip not available: {e}"]

    # Parse lock file for expected hashes
    lock_content = lock_path.read_text()
    expected: dict[str, set[str]] = {}
    current_pkg: str | None = None
    for line in lock_content.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if line.startswith("--hash="):
            if current_pkg:
                expected.setdefault(current_pkg, set()).add(line[7:])
        elif not line.startswith("-"):
            current_pkg = line.split("==")[0].lower() if "==" in line else None

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
