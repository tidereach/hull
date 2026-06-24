# Spektralia v1 — Phase 1: Deterministic Core

## Context

`spektralia_v1.md` is the authoritative spec for a local pre-cloud sensitivity gate: normalize → regex+entropy scan → sanitize → Ollama classifier → block/pass, with hash-chained audit, canary, freeze switch, and Claude Code hook integration.

Phase 1 covers the **synchronous detection pipeline** — no network, no audit chain yet. The goal is to verify pattern correctness and sanitizer guarantees in isolation, so that Phase 2 (which adds the classifier and gate orchestration) can build on a deterministic, well-tested foundation.

## Scope

The Phase 1 surface is nine source modules plus their tests, executed **TDD-style** per module: write failing tests first against the spec's expectations (§20 verification table), then implement to green.

**Module order:** `memory_safety` → `normalize` → `patterns` → `entropy` → `decode` → `scanner` → `sanitizer` → `integrity`, with `__init__.py` and `tests/conftest.py` set up first. Each module's tests must pass before moving on; final `pytest -q` green is the phase exit gate.

## Modules

- `__init__.py` — exports `SensitiveDataError`, `Settings` only at end of Phase 1
- `memory_safety.py` — `Secret(bytearray)` with `wipe()`, scrubbing `__repr__`/`__str__`, `PR_SET_DUMPABLE=0` at import on Linux
- `normalize.py` — NFKC, zero-width/bidi/variation-selector strip (each strip → `OBFUSCATION_CHAR` detection), homoglyph fold (Cyrillic/Greek/Armenian/Cherokee → Latin), offset map back to original; whitespace-collapsed shadow
- `patterns.py` — `Pattern(label, regex, validator, priority)` table; ships EMAIL, IP_ADDR, CVE, INTERNAL_HOST, CREDIT_CARD (+Luhn), NO_PID (+MOD-11), API_KEY_GENERIC (regex module, 100ms timeout → `REGEX_TIMEOUT`), AWS/Google/GitHub/Slack/Stripe prefixes, JWT (decode header, assert `alg`), PRIVATE_KEY_BLOCK, PRIVATE_KEY_BODY heuristic
- `entropy.py` — token-boundary Shannon entropy, allowlist for UUIDv4/git-SHA/file paths/base64-image markers
- `decode.py` — base64/hex/gzip unwrap, single level, re-scan → `<LABEL>_ENCODED` against outer span
- `scanner.py` — `Detection` dataclass (label+span only), runs patterns+entropy+decode against normalized+original+whitespace-collapsed shadows, dedupes overlapping spans (longer wins); IDN email shadow via IDNA-encoding
- `sanitizer.py` — `Sanitized` dataclass, `[REDACTED:LABEL:<6hex>]` tokens, per-request map in `Secret`s, private `_restore` with **JSONPath whitelist** + single-use semantics, never exported
- `integrity.py` — `pattern_hash` (sha256 of serialized pattern table), placeholder `model_digest`/`prompt_hash` for later
- `errors.py` — already exists, leave alone

## Tests

- `test_patterns.py`
- `test_normalize.py`
- `test_entropy.py`
- `test_decode.py`
- `test_scanner.py`
- `test_sanitizer.py`
- `test_no_secret_in_exceptions.py`
- `test_config_hash_covers_all_settings.py`
- `test_memory_safety.py`
- `corpus/{positive,negative,injection}/` seeded with a handful of fixtures
- `tests/conftest.py` minimal

## Reusable code

- `src/spektralia/config.py` — already has `Settings` + `config_hash` + `_non_policy` and a `policy_field` marker — keep as-is; `test_config_hash_covers_all_settings.py` exercises it
- `src/spektralia/errors.py` — `SensitiveDataError` already aligned with §13.5's actionable block-reason format; reuse unchanged
- Python stdlib: `unicodedata` (NFKC), `hashlib`, `secrets` (token suffixes), `base64`, `binascii`, `gzip`, `prctl` via `ctypes` for `PR_SET_DUMPABLE`
- Third party already pinned in `pyproject.toml`: `regex` (ReDoS-safe with `timeout=`); dev: `pytest`

## Gaps to close before Phase 2 starts

Reviewer (Ember, 2026-06-24) identified four Phase-1-owned items that slipped past the original implementation. Address them while Phase 1 modules are still the active surface.

1. **NFKC offset map is incorrect for length-changing codepoints.** `normalize.py` builds the offset map before the NFKC pass; codepoints like `ﬃ` (1 → 3 chars) misalign it, so `_remap_offset` returns the wrong original positions and the sanitizer replaces the wrong byte range. Fix by either folding length-changing characters in a pre-pass with a per-output-char source-index list, or by switching to a fully NFKC-then-strip pipeline whose offset map is built against the NFKC result. Add a test that scans an NFKC-expanding input containing a secret span and asserts the original-text span boundaries are correct.

2. **`tests/corpus/{positive,negative,injection}/` are empty.** Spec §20 expects positive-per-category fixtures, negative bait (UUIDs, SHAs, lorem, version strings), and injection payloads. Seed each directory with a handful of fixtures and have at least one scanner test consume them. The in-process `canary.py` is a separate mechanism (§13.3) and does not satisfy this.

3. **`_restore` is label-based, not JSONPath-based.** Spec §8 requires JSONPath expressions per call site, not global label prefixes. Today `_restore(text, sanitized, unsafe_restore_fields=["EMAIL"])` restores every EMAIL token globally — too coarse for Phase 3 hook restoration where only one specific field in one specific tool-input shape should round-trip. Change the contract to accept `unsafe_restore_paths: list[str]` (JSONPath against a structured payload) before Phase 3 wires hooks to it; update sanitizer tests accordingly. Keep the "private, single-use, never exported" invariants.

4. **`PR_SET_DUMPABLE=0` is called in `Gate.__init__`, not at module import.** Phase 1 intent ("at import on Linux") leaves CLI paths that use the scanner without instantiating a gate (`spektralia scan-config`, `spektralia verify-integrity`) handling sensitive data with core dumps enabled. Move the call into `memory_safety.py` module top-level (guarded for Linux, swallow failures).

## Exit criteria

- `pytest -q` green
- `python -c "from spektralia.scanner import scan; print(scan('alice@example.com 4111111111111111'))"` shows two detections
- `repr(secret)` never leaks value
- `python -c "from spektralia.config import Settings; print(Settings().config_hash())"` is stable across runs
- `pattern_hash` is deterministic
- Corpus directories non-empty and at least one scanner test consumes them
- NFKC-expanding sanitization round-trip test passes (span boundaries correct in original text)
- `PR_SET_DUMPABLE` was invoked on scanner-only import (no `Gate` instantiation)
- `_restore` accepts `unsafe_restore_paths` (JSONPath) and is not exported from the package
