#!/usr/bin/env python3
"""Red-team / bypass fuzz script.

For every positive corpus seed, applies deterministic obfuscation mutations
(NFKC-defeating chars, zero-width insertion, homoglyph substitution, base64/hex
wrapping, whitespace insertion, bidi overrides) and runs each variant through
gate() to check for bypasses.

Exit codes:
  0 — no seeds bypassed the gate (all detected after obfuscation)
  1 — one or more variants bypassed the gate (regression)

Run from repo root:
    .venv/bin/python scripts/redteam_fuzz.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Env setup BEFORE any spektralia imports
_STATE_DIR = tempfile.mkdtemp(prefix="spektralia_redteam_")
os.environ.setdefault("SPEKTRALIA_STATE_DIR", _STATE_DIR)
os.environ.setdefault("SPEKTRALIA_OLLAMA_URL", "http://127.0.0.1:11434")

import httpx
import respx

from spektralia.config import Settings
from spektralia.errors import SensitiveDataError
from spektralia.gate import Gate

REPO_ROOT = Path(__file__).parent.parent
CORPUS_DIR = REPO_ROOT / "tests" / "corpus"
MOCK_BASE = "http://127.0.0.1:11434"

# Mutation names and their transform functions.
# Each function takes a string and returns a mutated string.

# Zero-width space (U+200B) sprinkled into the secret
_ZWS = "​"
# Soft hyphen (U+00AD)
_SHY = "­"
# Left-to-right mark
_LRM = "‎"
# Cyrillic homoglyphs for ASCII letters (common substitutions)
_HOMOGLYPHS: dict[str, str] = {
    "a": "а",  # Cyrillic а
    "e": "е",  # Cyrillic е
    "o": "о",  # Cyrillic о
    "p": "р",  # Cyrillic р
    "c": "с",  # Cyrillic с
    "x": "х",  # Cyrillic х
    "A": "А",
    "E": "Е",
    "O": "О",
}


def _mut_zwsp(s: str) -> str:
    """Insert zero-width space after every 4th character."""
    parts = []
    for i, ch in enumerate(s):
        parts.append(ch)
        if (i + 1) % 4 == 0:
            parts.append(_ZWS)
    return "".join(parts)


def _mut_soft_hyphen(s: str) -> str:
    """Insert soft hyphen after every 3rd character."""
    parts = []
    for i, ch in enumerate(s):
        parts.append(ch)
        if (i + 1) % 3 == 0:
            parts.append(_SHY)
    return "".join(parts)


def _mut_lrm(s: str) -> str:
    """Prefix with left-to-right mark."""
    return _LRM + s


def _mut_homoglyph(s: str) -> str:
    """Substitute first occurrence of each mapped ASCII char with its Cyrillic homoglyph."""
    result = list(s)
    substituted: set[str] = set()
    for i, ch in enumerate(result):
        if ch in _HOMOGLYPHS and ch not in substituted:
            result[i] = _HOMOGLYPHS[ch]
            substituted.add(ch)
    return "".join(result)


def _mut_whitespace(s: str) -> str:
    """Insert a space after the first token boundary."""
    # Split on the first non-alphanumeric char (e.g. @ in email, _ in key)
    for i, ch in enumerate(s):
        if not ch.isalnum() and ch not in ("+", "/", "="):
            return s[:i] + " " + s[i:]
    # No boundary found — insert in the middle
    mid = len(s) // 2
    return s[:mid] + " " + s[mid:]


def _mut_base64_wrap(s: str) -> str:
    """Wrap the secret in a single layer of base64."""
    import base64
    return base64.b64encode(s.encode()).decode()


def _mut_hex_wrap(s: str) -> str:
    """Encode the secret as hex."""
    return s.encode().hex()


MUTATIONS: list[tuple[str, object]] = [
    ("zwsp", _mut_zwsp),
    ("soft_hyphen", _mut_soft_hyphen),
    ("lrm_prefix", _mut_lrm),
    ("homoglyph", _mut_homoglyph),
    ("whitespace", _mut_whitespace),
    ("base64_wrap", _mut_base64_wrap),
    ("hex_wrap", _mut_hex_wrap),
]


def _make_eval_settings() -> Settings:
    return Settings(
        rule_classifier_disagreement_rate_threshold=10.0,
        classifier_unavailable_rate_threshold=10.0,
    )


def _setup_mocks(router: respx.MockRouter) -> None:
    router.get(f"{MOCK_BASE}/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.1.0"})
    )
    router.get(f"{MOCK_BASE}/api/tags").mock(
        return_value=httpx.Response(200, json={"models": []})
    )
    router.post(f"{MOCK_BASE}/api/generate").mock(
        return_value=httpx.Response(
            200,
            json={"response": json.dumps({"sensitive": False, "confidence": 0.0, "categories": []})},
        )
    )


async def _is_blocked(text: str, gate_instance: Gate) -> bool:
    try:
        await gate_instance.gate(text)
        return False
    except SensitiveDataError:
        return True


async def _run() -> int:
    seeds = sorted((CORPUS_DIR / "positive").glob("*.txt"))

    bypasses: list[tuple[str, str, str]] = []  # (seed_name, mutation, variant)
    rows: list[tuple[str, str, bool, bool]] = []

    t0 = time.monotonic()

    with respx.mock(assert_all_called=False) as router:
        _setup_mocks(router)
        gate_instance = Gate(_make_eval_settings())

        for seed_path in seeds:
            seed_text = seed_path.read_text().strip()
            label = seed_path.stem.upper()

            # Verify seed itself is still blocked (sanity check)
            seed_blocked = await _is_blocked(seed_text, gate_instance)
            rows.append((label, "original", seed_blocked, True))

            for mut_name, mut_fn in MUTATIONS:
                variant = mut_fn(seed_text)
                blocked = await _is_blocked(variant, gate_instance)
                rows.append((label, mut_name, blocked, False))
                if not blocked:
                    bypasses.append((label, mut_name, variant[:80]))

    elapsed = time.monotonic() - t0

    # Print table
    print()
    print(f"{'LABEL':<22} {'MUTATION':<16} {'BLOCKED'}")
    print("-" * 46)
    for label, mutation, blocked, is_original in rows:
        mark = "BLOCK" if blocked else "PASS (bypass!)"
        tag = " *" if not blocked else ""
        print(f"{label:<22} {mutation:<16} {mark}{tag}")
    print()
    print(f"Elapsed: {elapsed:.1f}s  |  Seeds: {len(seeds)}  |  Variants: {len(rows)}")

    if bypasses:
        print(f"\nBYPASSES ({len(bypasses)}) — variants that slipped past gate():")
        for label, mutation, snippet in bypasses:
            print(f"  [{label}] {mutation}: {snippet!r}")
        print()
        print("These are canary candidates for A4 (canary_curator.py).")
        print()
        print("FAIL")
        return 1

    print("No bypasses found. PASS")
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
