# Spektralia v1 — phased implementation plan

## Context

`spektralia_v1.md` is the authoritative spec for a local pre-cloud sensitivity gate: normalize → regex+entropy scan → sanitize → Ollama classifier → block/pass, with hash-chained audit, canary, freeze switch, and Claude Code hook integration. The repo today contains only `pyproject.toml`, `src/spektralia/config.py`, and `src/spektralia/errors.py` (stubs). Everything else is empty directories.

The spec defines ~22 modules under `src/spektralia/`, ~20 test files, 6 Claude Code hooks, and two compliance/threat docs. It is too large to implement responsibly in one pass — and several layers (Ollama trust pinning, audit-chain persistence across restarts, hook integration with a real Claude Code session) want incremental verification rather than batch-and-pray.

This plan splits the work into four sequential phases. Each phase ends in a green `pytest -q` and an integratable surface. Phase boundaries are also natural review/commit points.

## Phase split

**Phase 1 — deterministic core (this session if you approve).** The synchronous detection pipeline, no network, no audit chain yet. Lets us verify pattern correctness and sanitizer guarantees in isolation.

- `__init__.py` — exports `SensitiveDataError`, `Settings` only for now
- `memory_safety.py` — `Secret(bytearray)` with `wipe()`, scrubbing `__repr__`/`__str__`, `PR_SET_DUMPABLE=0` at import on Linux
- `normalize.py` — NFKC, zero-width/bidi/variation-selector strip (each strip → `OBFUSCATION_CHAR` detection), homoglyph fold (Cyrillic/Greek/Armenian/Cherokee → Latin), offset map back to original; whitespace-collapsed shadow
- `patterns.py` — `Pattern(label, regex, validator, priority)` table; ships EMAIL, IP_ADDR, CVE, INTERNAL_HOST, CREDIT_CARD (+Luhn), NO_PID (+MOD-11), API_KEY_GENERIC (regex module, 100ms timeout → `REGEX_TIMEOUT`), AWS/Google/GitHub/Slack/Stripe prefixes, JWT (decode header, assert `alg`), PRIVATE_KEY_BLOCK, PRIVATE_KEY_BODY heuristic
- `entropy.py` — token-boundary Shannon entropy, allowlist for UUIDv4/git-SHA/file paths/base64-image markers
- `decode.py` — base64/hex/gzip unwrap, single level, re-scan → `<LABEL>_ENCODED` against outer span
- `scanner.py` — `Detection` dataclass (label+span only), runs patterns+entropy+decode against normalized+original+whitespace-collapsed shadows, dedupes overlapping spans (longer wins)
- `sanitizer.py` — `Sanitized` dataclass, `[REDACTED:LABEL:<6hex>]` tokens, per-request map in `Secret`s, private `_restore` with JSONPath whitelist + single-use semantics, never exported
- `integrity.py` — `pattern_hash` (sha256 of serialized pattern table), placeholder `model_digest`/`prompt_hash` for later
- `errors.py` — already exists, leave alone
- Tests: `test_patterns.py`, `test_normalize.py`, `test_entropy.py`, `test_decode.py`, `test_scanner.py`, `test_sanitizer.py`, `test_no_secret_in_exceptions.py`, `test_config_hash_covers_all_settings.py`, `corpus/{positive,negative,injection}/` seeded with a handful of fixtures
- `tests/conftest.py` minimal

Exit criteria: `pytest -q` green; `python -c "from spektralia.scanner import scan; ..."` produces correct detections on a sample input; pattern_hash deterministic.

**Phase 2 — audit, anomaly, classifier, cache, gate.** The async surface and the hash-chain backbone.

- `audit.py` — hash-chained records (`seq`, `prev_hash`, `record_hash`, times, action, labels, categories, confidence, hashes); `~/.spektralia/audit.state` persistence with `fsync`; `AuditSink` abstraction with `JournaldSink`/`SyslogSink`/`AppendOnlyFileSink`/`StdoutSink`; detection-based default; `audit-verify` logic
- `anomaly.py` — rolling counters over `window_seconds`, auto-freeze thresholds for classifier_unavailable, disagreement, canary_drift; override-rate audit-only
- `cache.py` — LRU(1024) keyed on `sha256(sanitized_text || config_hash)`; invalidation hooks for config/digest/pattern/prompt change, freeze/unfreeze, canary drift, self-test fail
- `ollama_trust.py` — UDS preferred path with `lstat` checks (S_ISSOCK, owner==EUID, mode 0600, owner-only parent); TCP fallback with PID + binary sha256 + version pin; model-digest pinned references; bind-mount heuristic; telemetry-status check
- `classifier.py` — httpx call to Ollama, `format:"json"`, `<input>…</input>` framing with escaping, two-framing consensus (`max`), `framing_disagreement` audit, enum-bounded categories, fail-closed on errors
- `canary.py` + `src/spektralia/canary/corpus/` — known-bad / known-safe / random-nonced payloads; drift → freeze
- `heartbeat.py` — periodic emission
- `gate.py` — `async gate(text, settings)` orchestration; `rule_hit OR classifier_high` block logic; soft mode + mutation-until-pass; `gate_sync` wrapper; `max_input_chars` deterministic block; `GateResult` exposes labels only
- `__init__.py` — add `gate`, `gate_sync`, `GateResult`
- Tests: `test_audit_chain.py`, `test_audit_no_values.py`, `test_anomaly.py`, `test_cache.py`, `test_canary.py`, `test_classifier.py` (respx-mocked), `test_ollama_trust.py`, `test_integrity.py`, `test_gate.py`

Exit criteria: `pytest -q` green with respx-mocked Ollama; `audit-verify` walks chain across simulated restart; canary drift triggers freeze.

**Phase 3 — CLI + hooks.**

- `cli.py` — versioned subcommand surface from §17 (scan/scan --explain, check-ollama, verify-integrity, verify-installed, self-test, stats, freeze/unfreeze, audit-verify, audit-rotate, audit-purge, scan-config, hook-check)
- `integrations/claude_code_hooks/{session_start,user_prompt_submit,pre_tool_use,post_tool_use,stop}.py`; `settings.example.json`; per-hook strict vs fast mode mapping; default-deny MCP matcher; attachment refusal; hook crash → block tests

Exit criteria: end-to-end manual scenario from spec §20 step 5 works against a scratch Claude Code config; `spektralia self-test` passes against a real local Ollama.

**Phase 4 — supply chain + docs + CI.**

- `requirements.lock` via `pip-compile --generate-hashes`
- `make sbom` target + committed `SBOM.json`
- `docs/COMPLIANCE.md`, `docs/THREATS.md`
- README with the verbatim disclaimer paragraph from §13.5
- CI: nightly ReDoS fuzz, per-hook latency budgets, `verify-installed` gate

## Reusable code I will lean on

- `src/spektralia/config.py` already has `Settings` + `config_hash` + `_non_policy` and a `policy_field` marker — keep as-is; Phase 1's `test_config_hash_covers_all_settings.py` exercises it
- `src/spektralia/errors.py` `SensitiveDataError` is already aligned with §13.5's actionable block-reason format — reuse unchanged
- Python stdlib: `unicodedata` (NFKC), `hashlib`, `secrets` (token suffixes), `base64`, `binascii`, `gzip`, `prctl` via `ctypes` for `PR_SET_DUMPABLE`
- Third party already pinned in `pyproject.toml`: `httpx`, `regex` (ReDoS-safe with `timeout=`), `keyring`; dev: `pytest`, `pytest-asyncio`, `respx`, `cyclonedx-bom`

## Files modified per phase

Phase 1 creates 9 source files + ~9 test files + corpus fixtures. Phase 2 creates 9 source files + 9 test files + canary corpus. Phase 3 creates 1 source file + 6 hook files + JSON. Phase 4 is mostly tooling and prose.

No file deletions; existing `config.py`/`errors.py` are appended to as new fields/exceptions become needed (e.g., Phase 2 adds audit-related settings).

## Verification per phase

- Phase 1: `pytest -q tests/` green; ad-hoc `python -c "import spektralia.scanner; print(spektralia.scanner.scan('alice@example.com 4111111111111111'))"` shows two detections; `repr(secret)` never leaks; running `python -c "from spektralia.config import Settings; print(Settings().config_hash())"` is stable across runs
- Phase 2: `pytest -q` green; `respx`-driven classifier test confirms two-framing consensus + injection corpus does not flip verdict; kill-and-restart simulation in `test_audit_chain.py` shows chain reanchors via `audit.state`
- Phase 3: install hooks into a scratch Claude Code config; reproduce §20.5 scenario (cat scratch `.env` → sanitized; `Task(prompt=...)` carrying secret → blocked; `Bash(curl -d [REDACTED:*:*])` → blocked); `spektralia self-test` green with live `ollama pull llama3.2:3b`
- Phase 4: `make sbom` regenerates without diff churn; `pip install --require-hashes -r requirements.lock` succeeds in clean venv; nightly ReDoS fuzz job dry-run

## Scope for this session (confirmed)

**Phase 1 only**, executed **TDD-style** per module: write failing tests first against the spec's expectations (§20 verification table), then implement to green. Module order: `memory_safety` → `normalize` → `patterns` → `entropy` → `decode` → `scanner` → `sanitizer` → `integrity`, with `__init__.py` and `tests/conftest.py` set up first. Each module's tests must pass before moving on; final `pytest -q` green is the phase exit gate.

Phases 2–4 are deferred to subsequent sessions and remain as documented above for continuity.

---

## Gaps discovered during review (2026-06-24)

Ember audited the in-tree implementation against the spec. The deterministic core, hash-chained audit, two-framing classifier, and Ollama trust pinning are well done. The following gaps must be closed **before or alongside** the affected component is touched in its phase. Items are scoped to the phase that owns the affected module, not the phase in which the gap was discovered.

### Phase 1 carry-overs (close before Phase 2 starts)

These slipped past Phase 1 because the code grew ahead of the spec contract. Address them while Phase 1 modules are still the active surface.

1. **NFKC offset map is incorrect for length-changing codepoints.** `normalize.py` builds the offset map before the NFKC pass; codepoints like `ﬃ` (1 → 3 chars) misalign it, so `_remap_offset` returns the wrong original positions and the sanitizer replaces the wrong byte range. Fix by either folding length-changing characters in a pre-pass with a per-output-char source-index list, or by switching to a fully NFKC-then-strip pipeline whose offset map is built against the NFKC result. Add a test that scans an NFKC-expanding input containing a secret span and asserts the original-text span boundaries are correct.
2. **`tests/corpus/{positive,negative,injection}/` are empty.** Spec §20 expects positive-per-category fixtures, negative bait (UUIDs, SHAs, lorem, version strings), and injection payloads. Seed each directory with a handful of fixtures and have at least one scanner test consume them. The in-process `canary.py` is a separate mechanism (§13.3) and does not satisfy this.
3. **`_restore` is label-based, not JSONPath-based.** Spec §8 requires JSONPath expressions per call site, not global label prefixes. Today `_restore(text, sanitized, unsafe_restore_fields=["EMAIL"])` restores every EMAIL token globally — too coarse for Phase 3 hook restoration where only one specific field in one specific tool-input shape should round-trip. Change the contract to accept `unsafe_restore_paths: list[str]` (JSONPath against a structured payload) before Phase 3 wires hooks to it; update sanitizer tests accordingly. Keep the "private, single-use, never exported" invariants.
4. **`PR_SET_DUMPABLE=0` is called in `Gate.__init__`, not at module import.** Phase 1 intent ("at import on Linux") leaves CLI paths that use the scanner without instantiating a gate (`spektralia scan-config`, `spektralia verify-integrity`) handling sensitive data with core dumps enabled. Move the call into `memory_safety.py` module top-level (guarded for Linux, swallow failures).

### Phase 2 corrections (close as part of Phase 2)

These are active correctness bugs in code that already exists under the Phase 2 boundary. Fix them inside Phase 2's normal scope rather than touching them later.

5. **Cache key uses raw text, not sanitized text.** Spec §15 requires `sha256(sanitized_text || config_hash)`. `gate.py` currently passes the original `text` to `LRUCache.make_key`. A future change to sanitization behavior could let a cached "pass" verdict escape against a payload that should now block. Move the cache lookup to **after** `sanitize()`, keyed on `result.text`.
6. **`config_hash` omits `pattern_hash`, `model_digest`, and `prompt_hash`.** Spec §15 explicitly requires all three in the cache key. `Settings.config_hash()` iterates only dataclass fields; pattern/model/prompt hashes live in `integrity.py` and `classifier.py` and are never folded in. Either extend `config_hash()` to accept and mix these three when called by the `Gate`, or have the `Gate` compute an effective cache key of `sha256(sanitized_text || config_hash || pattern_hash || model_digest || prompt_hash)`. Add a test that mutates each of the three hashes and asserts cache miss.
7. **Cache does not invalidate on freeze/unfreeze or self-test failure.** Spec §15's invalidation list includes both. Today only canary drift calls `invalidate_all()`. A "pass" cached before a freeze can be served on the first call after unfreeze. Wire `freeze()`, `unfreeze()`, and self-test failure into `LRUCache.invalidate_all()`; test the freeze/unfreeze round-trip explicitly.
8. **`SyslogSink` not implemented.** Spec §13.1 lists four sinks; only journald/file/stdout exist. Add the syslog sink and route `_choose_sink` through it on journald failure before falling back to the append-only file.
9. **`test_gate.py` and `test_ollama_trust.py` are required Phase 2 deliverables and currently absent.** `gate.py` (block decision, soft-mode mutation detector, freeze interaction, anomaly auto-freeze) and `ollama_trust.py` (UDS owner/mode rejection, TCP PID-pin change → freeze, model digest mismatch → freeze) carry the security-critical contracts of Phase 2 and must not ship without tests.

### Verification additions

- Phase 1 verification: add corpus directory non-empty check; add NFKC-expanding sanitization round-trip test; assert `PR_SET_DUMPABLE` was invoked on scanner-only import.
- Phase 2 verification: add cache-invalidation matrix test (pattern_hash change, model_digest change, prompt_hash change, freeze, unfreeze, canary drift, self-test fail) — each must produce a miss. `test_gate.py` and `test_ollama_trust.py` green is part of the Phase 2 exit gate.
