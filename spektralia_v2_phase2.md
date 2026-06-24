# Spektralia v1 — Phase 2: Audit, Anomaly, Classifier, Cache, Gate

## Context

Phase 1 delivered the deterministic detection pipeline (normalize → scan → sanitize). Phase 2 adds the **async surface and the hash-chain backbone**: the Ollama classifier (two-framing consensus, fail-closed), the gate orchestration (`rule_hit OR classifier_high`), the tamper-evident audit log that persists across restarts, the LRU cache, rolling anomaly counters with auto-freeze, the canary self-test, and the Ollama trust pinning (UDS preferred, TCP with PID + binary hash + version pin).

This is where the security-critical contracts of Spektralia live. Phase 2 must not ship without tests for the gate and trust pinning paths.

## Scope

The Phase 2 surface is nine source modules plus their tests, layered on top of the Phase 1 deterministic core.

## Modules

- `audit.py` — hash-chained records (`seq`, `prev_hash`, `record_hash`, times, action, labels, categories, confidence, hashes); `~/.spektralia/audit.state` persistence with `fsync`; `AuditSink` abstraction with `JournaldSink`/`SyslogSink`/`AppendOnlyFileSink`/`StdoutSink`; detection-based default; `audit-verify` logic
- `anomaly.py` — rolling counters over `window_seconds`, auto-freeze thresholds for classifier_unavailable, disagreement, canary_drift; override-rate audit-only
- `cache.py` — LRU(1024) keyed on `sha256(sanitized_text || config_hash || pattern_hash || model_digest || prompt_hash)`; invalidation hooks for config/digest/pattern/prompt change, freeze/unfreeze, canary drift, self-test fail
- `ollama_trust.py` — UDS preferred path with `lstat` checks (S_ISSOCK, owner==EUID, mode 0600, owner-only parent); TCP fallback with PID + binary sha256 + version pin; model-digest pinned references; bind-mount heuristic; telemetry-status check
- `classifier.py` — httpx call to Ollama, `format:"json"`, `<input>…</input>` framing with escaping, two-framing consensus (`max`), `framing_disagreement` audit, enum-bounded categories, fail-closed on errors
- `canary.py` + `src/spektralia/canary/corpus/` — known-bad / known-safe / random-nonced payloads; drift → freeze
- `heartbeat.py` — periodic emission
- `gate.py` — `async gate(text, settings)` orchestration; `rule_hit OR classifier_high` block logic; soft mode + mutation-until-pass; `gate_sync` wrapper; `max_input_chars` deterministic block; `GateResult` exposes labels only
- `__init__.py` — add `gate`, `gate_sync`, `GateResult`

## Tests

- `test_audit_chain.py`
- `test_audit_no_values.py`
- `test_anomaly.py`
- `test_cache.py`
- `test_canary.py`
- `test_classifier.py` (respx-mocked)
- `test_ollama_trust.py`
- `test_integrity.py`
- `test_gate.py`

## Reusable code

- `src/spektralia/config.py` already carries `policy_field` markers — extend `Settings` with audit/anomaly/classifier/cache fields, each annotated as policy or non-policy (`test_config_hash_covers_all_settings.py` from Phase 1 will fail loudly if you forget)
- Third party already pinned: `httpx`, `keyring`; dev: `pytest-asyncio`, `respx`
- Ollama: `ollama pull llama3.2:3b`

## Active correctness bugs to fix in Phase 2

Reviewer (Ember, 2026-06-24) identified five Phase-2-owned items in code that already exists. Fix them inside Phase 2's normal scope rather than treating them as separate work.

1. **Cache key uses raw text, not sanitized text.** Spec §15 requires `sha256(sanitized_text || config_hash)`. `gate.py` currently passes the original `text` to `LRUCache.make_key`. A future change to sanitization behavior could let a cached "pass" verdict escape against a payload that should now block. Move the cache lookup to **after** `sanitize()`, keyed on `result.text`.

2. **`config_hash` omits `pattern_hash`, `model_digest`, and `prompt_hash`.** Spec §15 explicitly requires all three in the cache key. `Settings.config_hash()` iterates only dataclass fields; pattern/model/prompt hashes live in `integrity.py` and `classifier.py` and are never folded in. Either extend `config_hash()` to accept and mix these three when called by the `Gate`, or have the `Gate` compute an effective cache key of `sha256(sanitized_text || config_hash || pattern_hash || model_digest || prompt_hash)`. Add a test that mutates each of the three hashes and asserts cache miss.

3. **Cache does not invalidate on freeze/unfreeze or self-test failure.** Spec §15's invalidation list includes both. Today only canary drift calls `invalidate_all()`. A "pass" cached before a freeze can be served on the first call after unfreeze. Wire `freeze()`, `unfreeze()`, and self-test failure into `LRUCache.invalidate_all()`; test the freeze/unfreeze round-trip explicitly.

4. **`SyslogSink` not implemented.** Spec §13.1 lists four sinks; only journald/file/stdout exist. Add the syslog sink and route `_choose_sink` through it on journald failure before falling back to the append-only file.

5. **`test_gate.py` and `test_ollama_trust.py` are required Phase 2 deliverables and currently absent.** `gate.py` (block decision, soft-mode mutation detector, freeze interaction, anomaly auto-freeze) and `ollama_trust.py` (UDS owner/mode rejection, TCP PID-pin change → freeze, model digest mismatch → freeze) carry the security-critical contracts of Phase 2 and must not ship without tests.

## Exit criteria

- `pytest -q` green with respx-mocked Ollama
- `respx`-driven classifier test confirms two-framing consensus + injection corpus does not flip verdict
- Kill-and-restart simulation in `test_audit_chain.py` shows chain reanchors via `audit.state`
- Canary drift triggers freeze (auto), surfacing through `spektralia stats`
- Cache-invalidation matrix test passes — each of the following produces a cache miss: pattern_hash change, model_digest change, prompt_hash change, freeze, unfreeze, canary drift, self-test fail
- `test_gate.py` and `test_ollama_trust.py` green (mandatory; not optional)
- `SyslogSink` exists and is reachable through `_choose_sink` fallback
