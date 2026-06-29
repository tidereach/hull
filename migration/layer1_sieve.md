# sieve — L1 Data Plane (sensitivity gate)

> **Layer name:** sieve.
> **Plane:** Data (L1).
> **Repo:** `tidereach/sieve`.
> **Status:** Migration spec; greenfield rebuild planned.

sieve is the data plane. It takes text in; classifies, scans, sanitises, and decides block / pass against a defined threat model. It is the canonical product the project (then named Spektralia) originally referred to — the sensitivity gate.

Read [`MAIN.md`](MAIN.md) first; it sets the architecture, the decisions, and the execution order. This file is sieve's slice.

---

## Mission

sieve owns content scanning. Concretely:

- **Deterministic detection**: regex + Luhn / MOD-11 validators + entropy + decoded-payload re-scan + IDN shadow.
- **Normalisation**: NFKC + zero-width / bidi / variation-selector strip + homoglyph fold; whitespace-collapsed shadow scan; offset map back to original.
- **Sanitisation**: random-suffix typed tokens (`[REDACTED:LABEL:<6hex>]`); per-request ephemeral map; no public `restore()`; opt-in `_restore` is schema-scoped (JSONPath) and single-use.
- **Classifier**: Ollama with `format: "json"`; two-framing consensus (`max`); injection-framed prompt; fail-closed; classifier-ambiguous handling.
- **Ollama trust channel**: UDS preferred (owner/mode lstat) → TCP fallback with PID + binary SHA-256 + version pin → fail-closed on any mismatch.
- **Memory hygiene**: `Secret(bytearray)` with `wipe()`; `PR_SET_DUMPABLE=0` at import on Linux; scrubbed `__repr__` / `__str__`.
- **Cache**: LRU keyed on `sha256(sanitized_text || effective_hash)` where `effective_hash` folds in pattern hash, model digest, prompt hash from interlock.
- **Gate orchestration**: `rule_hit OR classifier_high → block`; soft mode with mutation-until-pass detector; `--explain`; deterministic block on input size cap.
- **Opt-in NER** (`PERSON`, `LOC`, `ORG` via spaCy) for contextual PII.
- **Opt-in output gating** for finalised assistant turns (warn / block modes).

sieve does **not** own: lockfile / sandbox / hook-manifest verification (interlock), container / proxy / sandbox runtime (airlock), session-stream ingest / detection rules (jettison), intent / control rules (arbiter).

---

## Scope decision history

References [`MAIN.md § 7 Decisions locked`](MAIN.md#7-decisions-locked):

- **Row 2 (jettison = single module, deterministic-only)**: sieve keeps the LLM. jettison does not get its own classifier. Output gating in sieve stays deterministic-pipeline (no per-turn classifier call) per current SPEC §13.5.2.
- **Row 3 (4 sibling layer repos)**: sieve ships independently of airlock; jettison lives in-process within interlock per Decision 2. Cross-layer calls go through interlock services.
- **Row 6 (airlock owns substrate)**: `sessions/writer.py` is **deleted, not migrated**. sieve no longer carries the session-stream substrate. The agent CLI writes JSONL directly into airlock's mounted volume.
- **Row 8 (per-layer-file review)**: this file is reviewable standalone.

sieve is **Stage 3** in MAIN.md's execution order — develops in parallel with interlock (Stage 2); release requires a interlock release-candidate to be pinned.

---

## Doc audit

| Doc | Disposition for sieve | Notes |
|---|---|---|
| `docs/SPEC.md` §§4–10 | **Rewrite** | Rewrite per spec; the pre-migration invariants on patterns, normalisation, entropy, decode, sanitisation, and memory hygiene are sieve's deterministic core and carry forward unchanged in meaning. |
| `docs/SPEC.md` §11 Ollama trust channel | **Rewrite** | UDS / TCP / PID-pin contracts. Load-bearing for the classifier. |
| `docs/SPEC.md` §14 Gate orchestration | **Rewrite** | `rule_hit OR classifier_high`; `max_input_chars`; `gate_sync` semantics. |
| `docs/SPEC.md` §15 Cache | **Rewrite** | Rewrite per spec; the pre-migration cache key construction is correct and guides the rewrite. As part of the rewrite, extend the §15 invalidation list to include freeze, unfreeze, canary drift, and self-test fail (currently spec'd but inconsistently implemented). |
| `docs/SPEC.md` §16 Config | **Rewrite** | Precedence + validation. Apply to `sieveSettings`. |
| `docs/SPEC.md` §18 Claude Code integration | **Rewrite** | Rewrite per spec; sieve documents the integration contract while the hook scripts themselves are authored greenfield in hull (meta-repo). |
| `docs/SPEC.md` §22 Out of scope | **Rewrite** | Rewrite per spec; carry forward the sieve-applicable items (HTTPS-MITM, persistent cache, kernel-level attackers). Out-of-scope items belonging to other layers reappear in their respective layer specs. |
| `docs/RATIONALE.md` v2 | **Rewrite** | Rewrite per spec; the pre-migration narrative on reversible-tokenisation demotion, provider-key patterns, and two-framing consensus supplies the "why" behind each deterministic-core decision and is re-summarised in the sieve v1 spec text. |
| `docs/RATIONALE.md` v4 §1–§4, §8, §10 | **Rewrite** | Ollama trust, memory hygiene, detection blindspots, UX failure modes, ReDoS. All sieve concerns. |
| `docs/THREATS.md` | **Rewrite** | sieve's threat model. Layer-cross-referenced items (sandbox, control engine) link to airlock / arbiter respectively. |
| `docs/COMPLIANCE.md § PCI-DSS, § GDPR (sections on PII detection)` | **Rewrite** | PAN detection (Luhn) and NO_PID detection (MOD-11) are sieve's compliance surface. |
| `AGENTS.md` Gotchas — entropy allowlist invariant (#22) | **Rewrite** | Critical correctness invariant for `entropy.py`. |
| `AGENTS.md` Gotchas — `gate() raises not returns` | **Rewrite** | Public API contract. |
| `AGENTS.md` Gotchas — `TOML config requires [spektralia]` section | **Rewrite** | Rewrite per spec; the pre-migration gotcha guides the section-naming convention. Rename the section from `[spektralia]` to `[sieve]` in sieve's TOML schema. |
| `AGENTS.md` Gotchas — `llama3.2:3b produces false positives` | **Rewrite** | Known classifier-model failure mode; sieve v1 enforces `llama3.1:8b` as the documented default. |
| `AGENTS.md` Gotchas — self-scan exclusion | **Rewrite** | Rewrite per spec; the pre-migration path-keyed exclusion pattern guides the design. As part of the rewrite, de-hardcode the path: `/src/spektralia/` becomes the configurable `sieveSettings.self_paths`. |
| `AGENTS.md` Gotchas — macOS test skip, `recheck not on PyPI` | **Rewrite** | Test-environment notes. |
| `docs/ENDPOINT_STACK.md § How cplt-sndbx wraps the agent + § Posture` | **Rewrite** | sieve-side framing for the layered stack; airlock's allow-list must permit Ollama (or sieve fails closed). |
| `integrations/claude/README.md`, `integrations/claude/AGENTS.md` | **Stay in hull (meta-repo)** | Hook scripts move with the meta-repo; sieve's doc references them by URL. |

**Doc reconciliation tasks**:

1. `docs/SPEC.md §15` invalidation list reconciled with actual code paths during the Stage 3 cache rewrite.
2. References to `sessions/writer.py` removed from all sieve docs; the substrate role is airlock's.

---

## Lessons learned

- **`OBFUSCATION_CHAR` dedupe suppression** (Phase 1 bug). The original dedupe in `scanner._dedupe` silenced audit-visible markers when overlapping a larger secret span. *Lesson:* audit-visible events must not be silenced by overlap dedupe. *v1:* `_ALWAYS_EMIT` list is part of the public contract; new audit-marker labels enrol there explicitly; tests assert per-label presence.

- **NFKC offset map mismatch for length-changing codepoints** (carry-over #1). `ﬃ` (one char → three) misaligned `_remap_offset`, so the sanitiser replaced the wrong byte range. *Lesson:* build offset maps against NFKC *output*, not input. *v1:* `normalize.py` builds a per-output-char source-index list during the NFKC pass; test for NFKC-expanding input lands at v1 release.

- **`tests/corpus/{positive,negative,injection}/` empty in v1 ship** (carry-over #2). Spec §20 required them; the directories existed but were unseeded. *Lesson:* corpus directories are required test surface, not optional. *v1:* corpus fixtures land at sieve v1 release; CI fails if any subdirectory is empty.

- **`_restore` was label-based, not JSONPath-based** (carry-over #3). `unsafe_restore_fields=["EMAIL"]` restored every EMAIL token globally — too coarse for hook restoration. *Lesson:* integrator-facing restore must be schema-scoped, not type-scoped. *v1:* `unsafe_restore_paths: list[JSONPath]`; single-use; never auto-invoked.

- **`PR_SET_DUMPABLE=0` called in `Gate.__init__`, not at module import** (carry-over #4). CLI paths like `scan-config` ran without the prctl call. *Lesson:* memory hygiene must fire on any sieve import path. *v1:* `memory_safety.py` calls `prctl` at module import on Linux; failure swallowed.

- **Cache key originally used raw text, not sanitised text** (Phase-2 bug #5). A future sanitisation-behaviour change could let a cached "pass" verdict escape against a payload that should now block. *Lesson:* cache after `sanitize()`. *v1:* `Cache.lookup` called only on `result.text`, never on the original `text`.

- **`config_hash` missed `pattern_hash`, `model_digest`, `prompt_hash`** (Phase-2 bug #6). Editing a regex did not invalidate the cache. *Lesson:* policy-affecting hashes external to `Settings` must still fold into the effective cache key. *v1:* explicit `effective_cache_key(sanitized_text, settings, interlock_hashes) -> bytes` function; tests mutate each hash and assert cache miss.

- **Cache did not invalidate on freeze / unfreeze / self-test failure** (Phase-2 bug #7). A "pass" cached before a freeze could be served on the first call after unfreeze. *Lesson:* invalidation list is part of the spec, not an afterthought. *v1:* `Cache.invalidate_all()` wired to every documented trigger (pattern_hash change, model_digest change, prompt_hash change, freeze, unfreeze, canary drift, self-test fail); test per-trigger.

- **`SyslogSink` shipped late** (Phase-2 bug #8). Sink choice depended on detection, but only journald / file / stdout were implemented in early v1. *Lesson:* sink fallback chain is a security property. *v1 (interlock-side):* all sinks land at v1; `_choose_sink` covers every transition. *sieve uses interlock's sinks via the `AuditChain` API.*

- **`llama3.2:3b` returned `sensitive=True, confidence=1.0, categories=[]`** on benign short text. The classifier defaulted fail-closed on ambiguity. *Lesson:* an empty-categories analyzer that does not block is necessary or short benign text always blocks. *v1:* explicit handling of `confidence ≥ threshold AND categories == []` — emit `classifier_ambiguous` audit event and apply rule-only verdict (no classifier-driven block). Documented as a classifier-model limitation.

- **Pre-tool-use self-scan exclusion is path-keyed (`/src/spektralia/`)**. The hook skipped any file path containing the literal substring. *Lesson:* gate's own source files should not be gated against the gate. *v1:* still path-keyed but the exclusion set is `sieveSettings.self_paths: list[str]` rather than hardcoded; the integrator can extend it.

- **`recheck`-based ReDoS fuzz never worked** (`recheck` not on PyPI). *Lesson:* build CI tooling on stdlib + the runtime regex engine's own timeout, not on a vendored fuzzer. *v1:* `scripts/redos_fuzz.py` is the pure-Python timeout assertion (all patterns return within 100ms `regex.timeout`).

- **Hook known issues #55-59** (self-scan FP, empty-categories block, `UnboundLocalError` without venv, wrong JSON output shape, `Task` vs `Agent` tool name). *Lesson:* integration hooks need contract tests against a canonical fixture transcript; the gate's source is not the integration surface. *v1:* each hook script (which lives in hull meta-repo) ships with a transcript fixture; tests assert the JSON output shape and the matcher set; interlock's `hook-check` consumes the fixture.

- **`gate()` was an implicit top-level function with global state** in the monolith. v1 keeps that affordance for operator convenience (`from sieve import gate`) but layers an explicit `Gate` class underneath for testability and dependency clarity. The hybrid follows the `logging` module pattern (root logger + module-level `info()` for simple use; explicit `Logger` instances for advanced use).

---

## Reuse table

| Source (current) | Disposition | Notes |
|---|---|---|
| `src/spektralia/patterns.py` | **Rewrite** | Clean leaf; `regex` module + base64 + json + re only. Provider key prefixes, JWT, Luhn-backed CC, MOD-11-backed NO_PID — all correct. |
| `src/spektralia/normalize.py` | **Rewrite** | Rewrite per spec; the pre-migration NFKC pipeline guides the design. As part of the rewrite, fix carry-over #1: build offset maps against NFKC output (not input) so length-changing codepoints land correctly. v1 release acceptance requires the NFKC-expanding round-trip test. |
| `src/spektralia/scanner.py` | **Rewrite** | Detection dataclass, `scan()`, span dedupe, `_ALWAYS_EMIT`, IDN shadow. |
| `src/spektralia/entropy.py` | **Rewrite** | Allowlist invariant documented (#22); matcher table is the contract. |
| `src/spektralia/decode.py` | **Rewrite** | Single-level unwrap (base64 / hex / gzip). |
| `src/spektralia/memory_safety.py` | **Rewrite** | Rewrite per spec; the pre-migration memory-hygiene primitives guide the design. As part of the rewrite, fix carry-over #4: call `PR_SET_DUMPABLE=0` at module import (Linux) so every sieve import path is covered, not only `Gate.__init__`. |
| `src/spektralia/sanitizer.py` | **Rewrite** | Rewrite per spec; the pre-migration sanitiser pipeline guides the design. As part of the rewrite, fix carry-over #3: `_restore` is JSONPath-scoped (`unsafe_restore_paths: list[JSONPath]`), single-use, never auto-invoked — replacing the coarse label-based restore (`unsafe_restore_fields=["EMAIL"]`) that restored every token of a type. |
| `src/spektralia/cache.py` | **Rewrite** | LRU contract is documented. Cache *use* changes in `gate.py` (cache after sanitise; invalidation triggers); the pre-migration cache *implementation* shape guides the rewrite. |
| `src/spektralia/classifier.py` | **Rewrite** | Rewrite per spec; the pre-migration two-framing + format=json + fail-closed design guides the rewrite. As part of the rewrite, handle the classifier-ambiguous case explicitly: `confidence ≥ threshold AND categories == []` emits a `classifier_ambiguous` audit event and applies a rule-only verdict (no classifier-driven block). |
| `src/spektralia/ollama_trust.py` | **Rewrite** | UDS + TCP + PID pin. |
| `src/spektralia/gate.py` | **Rewrite** | Hub; currently imports 14 modules and owns freeze / audit / integrity instantiation. v1: `Gate` calls into interlock's `FreezeManager`, `AuditChain`, `IntegrityHasher`; orchestration logic (rule_hit OR classifier_high; soft mode; mutation detector) carries forward in intent only — every line is authored greenfield. |
| `src/spektralia/output_gate.py` | **Rewrite** | Stateless; finalised-turn scan via the same deterministic pipeline; marked as sieve's public output-gating API. |
| `src/spektralia/ner.py` | **Rewrite** | Stateless; opt-in; spaCy via `[ner]` extra. |
| `src/spektralia/errors.py` | **Rewrite** | `SensitiveDataError` is the public exception. |
| `src/spektralia/config.py` (sieve subset) | **Rewrite** | New `sieveSettings` with 15 sieve fields; the pre-migration `from_env` (`sieve_*`) / `from_toml` (`[sieve]`) / `config_hash` patterns guide the rewrite; the file is authored greenfield. |
| `src/spektralia/cli.py` (sieve subset) | **Rewrite** | `scan`, `scan --explain`, `scan-config`, `self-test`. The pre-migration argparse skeleton informs the structure; subcommand bodies are authored greenfield against interlock services for verify-* / freeze / audit. |
| `src/spektralia/sessions/writer.py` | **Drop** | airlock substrate obsoletes it. |
| `src/spektralia/sessions/__init__.py` | **Drop** | Empty. |
| `integrations/claude/hooks/*.py` | **Stay in hull (meta-repo)** | Hook scripts move with the meta-repo, not into sieve. |
| `integrations/copilot/hooks/*.py` | **Stay in hull (meta-repo)** | Same. |
| `integrations/claude/settings.example.json` | **Stay in hull (meta-repo)** | Reference hook configuration. |
| `integrations/copilot/spektralia.json` | **Stay in hull (meta-repo)** | Reference Copilot hook configuration. |
| `tests/corpus/{positive,negative,injection}/` | **Rewrite (seed)** | Currently empty; seed at sieve v1 release with positive-per-category, negative bait, injection payloads. |
| `scripts/eval_gate.py` | **Rewrite** | Eval harness. |
| `scripts/threshold_sweep.py` | **Rewrite** | Threshold tuning. |
| `scripts/redteam_fuzz.py` | **Rewrite** | Red-team corpus runner. |
| `scripts/redos_fuzz.py` | **Rewrite** | ReDoS fuzz; pure-Python timeout assertion. |
| `scripts/latency_bench.py` | **Rewrite** | Per-hook p95 budget. |
| `scripts/canary_curator.py` | **Rewrite** | Canary corpus curator. |
| `scripts/eval_baseline.json` | **Rewrite** | Re-baselined post-Stage 3 against the rewritten sieve. The pre-migration baseline informs expected ranges; the numbers may shift slightly after the carry-over fixes. |
| Tests (`test_patterns.py`, `test_normalize.py`, `test_scanner.py`, `test_entropy.py`, `test_decode.py`, `test_sanitizer.py`, `test_memory_safety.py`, `test_cache.py`, `test_classifier.py`, `test_ollama_trust.py`, `test_gate.py`, `test_output_gate.py`, `test_ner.py`, `test_corpus.py`, `test_no_secret_in_exceptions.py`, `test_config_hash_covers_all_settings.py`, `test_config_loading.py`, `test_errors.py`) | **Rewrite** | Tests reference unified `Settings`; greenfield rewrite against `sieveSettings`. Test data and corpus payloads are likewise re-authored greenfield against the new fixture format. |
| Tests (`test_audit_*.py`, `test_anomaly.py`, `test_canary.py`, `test_integrity.py`, `test_hook_manifest.py`, `test_sandbox*.py`, `test_heartbeat.py`, `test_sessions_writer.py`) | **Drop from sieve** | Belong in interlock (or deleted for `test_sessions_writer.py`). |
| `tests/test_hooks.py`, `tests/test_cli.py` | **Split** | Hook-script bodies test under hull (meta-repo); CLI subcommand tests split per-layer. sieve keeps `scan / scan --explain / scan-config / self-test` tests. |

---

## v1 spec

### Public API

A Python library exposing:

- `class Gate(settings: sieveSettings, freeze_manager: interlock.FreezeManager, audit_chain: interlock.AuditChain, integrity_hasher: interlock.IntegrityHasher, anomaly_counter: interlock.AnomalyCounter)` — **primary contract**. Explicit dependency injection. Construct once at process startup; reuse for all `gate()` calls. Method `async def gate(text: str) -> GateResult`. Raises `SensitiveDataError` on hard block (strict mode); returns `GateResult(blocked=True)` only in soft mode.
- `async def gate(text: str, settings: sieveSettings | None = None) -> GateResult` — **module-level convenience**. Wraps a lazily-constructed process-singleton `Gate` using `sieveSettings.from_env_or_toml()` + interlock defaults from `_construct_default_gate()`. Hook scripts and simple integrations use this; tests and advanced integrations construct `Gate` directly. **Trade-off explicit:** the singleton is mutable global state; long-running processes wanting to reconfigure mid-flight must reset the default explicitly (configure-then-run is the assumed pattern).
- `def gate_sync(text: str, settings: sieveSettings | None = None) -> GateResult` — `asyncio.run` wrapper; raises if called inside a running event loop. Thread-unsafe by default.
- `class GateResult(sanitized_text: str, detections: list[Detection], classifier_result: ClassifierResult, blocked: bool)` — labels and spans only; no values.
- `class SensitiveDataError(Exception)` — `categories: list[str]`, `reason: str`.
- `class sieveSettings` (dataclass) — see Settings table below.
- `class OutputGate(settings: sieveSettings)` — `.scan_turn(finalized_text: str) -> OutputGateResult` for finalised assistant turns.
- `Sanitized` private dataclass exposing `.text` publicly and `._token_map` privately; `_restore(text, sanitized, *, unsafe_restore_paths: list[str])` accepts JSONPath expressions; single-use; never exported from `__init__`.

### Module map

```
src/sieve/
├── __init__.py                 # public API
├── config.py                   # sieveSettings
├── errors.py                   # SensitiveDataError
├── patterns.py                 # Pattern table, validators
├── normalize.py                # NFKC, obfuscation strip, homoglyph fold, whitespace shadow
├── scanner.py                  # Detection, scan(), span dedupe, IDN shadow
├── entropy.py                  # Shannon entropy, allowlist
├── decode.py                   # base64 / hex / gzip unwrap + re-scan
├── memory_safety.py            # Secret(bytearray), wipe(), PR_SET_DUMPABLE at import
├── sanitizer.py                # random-suffix tokens, _restore (JSONPath, single-use)
├── classifier.py               # Ollama format=json, two framings, classifier-ambiguous handling
├── ollama_trust.py             # UDS preferred; TCP with PID/exe-hash/version pin fallback
├── cache.py                    # LRU keyed on sha256(sanitized_text || effective_hash)
├── gate.py                     # exports: Gate, gate, GateResult, SensitiveDataError; orchestration, soft mode, --explain, max_input_chars
├── output_gate.py              # finalised assistant turn scanning
├── ner.py                      # opt-in spaCy NER (PERSON, LOC, ORG)
└── cli.py                      # scan, scan --explain, scan-config, self-test
```

interlock integration:

- Gate receives `FreezeManager`, `AuditChain`, and `IntegrityHasher` as injected dependencies (see injection constraint in Public API above).
- `gate()` calls `interlock.FreezeManager.check()` before any pipeline work.
- Every block / pass / warn / anomaly event is emitted via `interlock.AuditChain.append`.
- The canary runner is constructed by interlock; sieve provides the scan callable.

Cache invalidation — two distinct mechanisms:

- **Hash drift (key-miss)**: `effective_cache_key(sanitized_text, settings, interlock_hashes)` incorporates `pattern_hash`, `model_digest`, `prompt_hash`, `normalization_map_version`, and the full policy `config_hash`. When any of these change, the key changes and old entries miss naturally. No explicit `Cache.invalidate_all()` call is needed for hash-change triggers.
- **State events (`Cache.invalidate_all()`)**: `freeze`, `unfreeze`, `canary_drift`, `self-test fail`. These change no hashes, so the cache key is unchanged and old entries would be served without explicit invalidation. `Cache.invalidate_all()` must be wired to each of these four state events and tested per-trigger.

The v1 verification requirement ("cache invalidation matrix tested per-trigger") must test both mechanisms separately: hash-change triggers via key-miss assertion, state-event triggers via `invalidate_all()` call assertion.

### CLI

`tidereach sieve` umbrella subcommand (per Decision 16; the in-repo `sieve = "tidereach.sieve.cli:main"` entry point exists for test invocation but is not installed on PATH). Versioned: `tidereach sieve --api-version`.

**No console script.** This layer's package (`tidereach-sieve`) registers no console script per Decision 16; invocation is via `tidereach sieve <subcommand>` (umbrella; owned by `tidereach-interlock`) or `python -m tidereach.sieve` (in-repo testing via `__main__.py`).

| Subcommand | Function |
|---|---|
| `scan` | stdin → sanitised stdout; exit 0 on pass, exit 2 on block (categories on stderr). |
| `scan --explain` | Verbose mode: which detectors ran, what they found, classifier categories, block reason. Labels only. |
| `scan-config` | Lint `~/.claude/CLAUDE.md` and project `CLAUDE.md` files for sensitive content using the same gate. |
| `self-test` | Run the canary corpus against the live classifier; print per-payload pass/fail. |

### Settings (`sieveSettings`)

20 fields. Each policy-marked or non-policy-marked; `config_hash()` excludes non-policy.

| Field | Type | Default | Policy |
|---|---|---|---|
| `ollama_url` | `str` | `http://127.0.0.1:11434` | yes |
| `ollama_socket` | `Path \| None` | `None` | yes |
| `ollama_model` | `str` | `llama3.1:8b` | yes |
| `ollama_model_digest` | `str \| None` | `None` | yes |
| `ollama_auth_header` | `str \| None` | `None` | no |
| `classifier_mode` | `Literal["strict","fast"]` | `"strict"` | yes |
| `classifier_timeout_seconds` | `int` | `10` | no |
| `sensitivity_threshold` | `float` | `0.7` | yes |
| `framing_disagreement_threshold` | `float` | `0.3` | yes |
| `mode` | `Literal["strict","soft"]` | `"strict"` | yes |
| `fail_open` | `bool` | `False` | yes |
| `max_input_chars` | `int` | `100_000` | yes |
| `cache_size` | `int` | `1024` | no |
| `mlock_secrets` | `bool` | `False` | yes |
| `ner_enabled` | `bool` | `False` | yes |
| `ner_model` | `str` | `en_core_web_sm` | yes |
| `normalization_map_version` | `str` | `"v1"` | yes |
| `gate_outputs` | `bool` | `False` | yes |
| `gate_outputs_mode` | `Literal["warn","block"]` | `"warn"` | yes |
| `self_paths` | `list[str]` | `["/src/sieve/"]` | no |

Precedence: kwargs > env (`sieve_*`) > TOML (`[sieve]`) > defaults.

`gate_outputs` and `gate_outputs_mode` are policy fields: two instances with different output gating configurations must not share cache entries.

`self_paths` is non-policy by design: changes to `self_paths` affect which call sites reach `gate()` at all, not the scan behaviour on content that does reach it. A `self_paths` change does not bust the cache.

### Audit events owned

- `block` — categorised by reason: `input_too_large`, `REGEX_TIMEOUT`, `classifier_unavailable`, `rule+classifier`, `classifier_only`, `rule_only`.
- `warn` — soft-mode acceptance.
- `pass` — clean payload.
- `classifier_unavailable` — Ollama outage.
- `framing_disagreement` — two-framing `max - min > threshold`.
- `rule_classifier_disagreement` — rule passes, classifier flags (or vice versa).
- `mutation_pattern_detected` — third same-category soft-override in a window.
- `user_override` — soft-mode override.
- `hallucinated_token_seen` — token reference in a non-tool context.
- `attachment_seen_unscanned` — attachment refused or accepted under `--allow-attachments`.
- `output_flagged` — finalised assistant turn matched the deterministic pipeline.
- `classifier_ambiguous` — `confidence ≥ threshold AND categories == []`; rule-only verdict applied. `classifier_ambiguous` is not fail-closed — it routes to rule-only verdict, which may pass or block depending on the deterministic pipeline result. It is not the same as `classifier_unavailable`.

### Cross-layer contracts honoured

- **Required dependency**: `interlock-contracts @ file:./vendor/interlock-contracts` (PEP 508 path-dep) in `pyproject.toml`. Stage 3 cannot start without an initialized `interlock-contracts` submodule. **Operator note:** sieve consumers run `git submodule update --init --recursive` after clone before `pip install`; the pinned contracts SHA is recorded in `.gitmodules` and surfaced in `README.md`.
- Calls `interlock.FreezeManager.check()` first thing in `gate()`.
- Calls `interlock.AuditChain.append(AuditRecord)` per event, matching the audit-envelope schema in interlock `contracts/audit-envelope/v1`.
- Calls `interlock.IntegrityHasher.compute(pattern_input, prompt_input, model_input)` at Gate init; provides `HashInput` implementations for each, per `contracts/integrity-inputs/v1.0.0/`.
- Honours the hook-manifest schema when the meta-repo's hook scripts invoke sieve — fixture-driven matcher / tool-name assertions per interlock `contracts/hook-manifest/v1`.
- Ollama trust events (`ollama_socket_untrusted`, `ollama_identity_changed`, `ollama_telemetry_status_unknown`, `ollama_shared_socket_warning`) are defined and versioned by interlock but **emitted by sieve** via `ollama_trust.py`. These are cross-layer events with a defined namespace, not layer-exclusive events. See `governance/audit-event-ownership.md` two-tier model.

### Verification

- `pytest -q` green, ≥ 215 tests including corpus tests for the newly-seeded `tests/corpus/`.
- Live e2e against `llama3.1:8b`: credential block at UserPromptSubmit (`sk_live_*`); Agent prompt with email blocked; Bash prompt with email blocked; `tidereach sieve self-test` green. (Reproduces `docs/PLAN.md § 3.19` 2026-06-25 e2e on the new repo.)
- Latency budgets: UserPromptSubmit ≤ 500ms p95; PreToolUse ≤ 300ms p95; PostToolUse ≤ 200ms p95 on 10KB. **Gate**: `scripts/latency_bench.py` runs 100 requests per hook type against a respx-stubbed classifier (configurable sleep, default 80ms, to simulate model latency). Pass threshold: p95 within budget, **zero tolerance** (hard fail, not warning). The stubbed bench tests sieve's pipeline overhead (normalisation, gate orchestration, cache) — not Ollama's model latency, which is exogenous and hardware-dependent. **Stage 3 acceptance** additionally runs the bench against a live `llama3.1:8b` instance on the sign-off machine; the live run result is recorded in the Stage 3 gate checklist but does not gate CI merges (model latency varies by hardware and would make CI non-deterministic). Hardware variance in CI is not a valid skip reason — if CI hardware cannot hit the stubbed budget, the sieve implementation is too slow.
- ReDoS: every pattern returns within the 100ms `regex.timeout` guard; nightly `redos-fuzz.yml`-equivalent runs.
- Cache invalidation matrix: pattern_hash, model_digest, prompt_hash, freeze, unfreeze, canary drift, self-test fail each produce a cache miss; tested per trigger.
- Two-framing consensus: injection corpus does not flip verdict; `framing_disagreement` event emitted on disagreement.
- Memory hygiene: known-secret byte sequence not findable in any `Secret` buffer post-gate; every exception path on known-secret input contains no value (`test_no_secret_in_exceptions.py`).
- Compliance: `test_audit_no_values.py` fuzzes the audit interface; no field ever contains a known secret.
- `Gate` / `gate()` parity: tests construct `Gate(...)` directly with mocks; the `gate()` module-level convenience path is tested against a fixture interlock setup; both paths reach the same code.

---

## v2 spec

- **Per-org pattern packs** — operator-published, optionally signed via interlock v2 attestation. Allows orgs to add domain-specific patterns (industry codes, internal identifiers) without forking sieve.
- **Alternative classifiers** — sglang, llama.cpp, vLLM. The classifier interface abstracts Ollama; alternative backends honour the same two-framing consensus + format=json contract.
- **Possibly move `ollama_trust` to interlock** as a generic "trusted local service" preflight that arbiter's `check-engine` and sieve's classifier both consume. Open question; defer to v2 design.
- **Classifier-based output gating** — currently `gate_outputs_mode` is rule-deterministic only (no classifier call per turn). v2 may add an opt-in mode that runs the classifier on finalised turns; cost is latency.
- **Persistent / distributed cache** — current v1 is in-process LRU; v2 may add an opt-in Redis backend with the same timing-leak threat model documented.

---

## Out of scope

- **Lockfile verification, sandbox check, hook-manifest check, audit chain management, freeze switch, canary corpus management** — interlock.
- **Container runtime, Squid proxy ACLs, Landlock policy, seccomp profile, session-stream volume mount** — airlock.
- **Session-stream ingest, behavioural detection rules, Block / Vent actions** — jettison.
- **Intent policy / control engine selection** — arbiter (and operator).
- **Hook script bodies, settings.example.json** — hull (meta-repo).
- **Network MITM on the Anthropic API, kernel-level local attackers, side-channels across tenants, attacks on the Ollama binary itself** — out of sieve's threat model (cf. `docs/THREATS.md`).
- **Contextual PII detection beyond opt-in NER** — known gap; documented.
- **Streaming / chunked input** — callers must buffer before `gate()`.
- **HTTPS-MITM proxy integration** — explicitly out of scope.
- **Cryptographic signing of the audit chain (just hashing)** — interlock v2.

---

## Open questions for v2

- **`ollama_trust` migration to interlock**: is the trust channel a sieve concern (it owns the classifier) or a interlock concern (it owns service-presence checks)? v1 keeps it in sieve; v2 may move.
- **Signed pattern packs**: depends on interlock v2 attestation landing first.
- **Cross-org pattern federation**: shared corrections to false positives; reputation-weighted distribution. Requires interlock v2 trust roots.
- **Alternative classifier backends**: which to support first? Operator demand will pick.
- **Classifier-based output gating**: latency budget vs detection lift. Field data needed.
