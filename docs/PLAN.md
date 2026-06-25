# Spektralia — Plan, Spec, and Status

A local pre-cloud sensitivity gate. Two layers of deterministic detection (regex + entropy), normalization to strip obfuscation, sanitization to typed placeholders, a small local Ollama classifier as second signal, then a block/pass decision delivered through hash-chained tamper-evident audit. Built to be embedded in Claude Code (or any agent) via hooks. Built to be hostile to its own users only when the alternative is leaking secrets.

> **Status (2026-06-25):** Phase 1 complete (109 tests passing, all deterministic-core modules built). Phase 2 complete (165 tests passing; all carry-overs closed; `test_gate.py`, `test_ollama_trust.py`, cache-invalidation matrix, SyslogSink all green). Phase 3 complete (215 tests passing; CLI all subcommands including `audit-rotate`/`audit-purge`; all five hooks refactored with `handle()` for testability; MCP default-deny fixed to `mcp__` prefix; `test_hooks.py`/`test_cli.py` passing; hooks README written; §3.19 live e2e verified 2026-06-25: credential block, email block via Agent prompt, email block via Bash prompt, self-test all green). Phase 4 complete and manually verified (225 tests passing; Makefile, SBOM.json, docs/COMPLIANCE.md, docs/THREATS.md, README §13.5 disclaimer, scripts/latency_bench.py, scripts/redos_fuzz.py, GitHub Actions ci.yml/latency.yml/redos-fuzz.yml all done; §4.1–§4.6 manual checks all pass; PR #3 open).

> **Related files:** `SPEC.md` (full 22-chapter spec), `RATIONALE.md` (design arguments from v2/v3/v4 proposals), `README.md` (key decisions by phase with spec §§ references).

---

## 1. How we got here — decision history

The plan went through four drafts before crystallizing into the current spec. Each draft addressed a specific reviewer critique; the insights they introduced are now part of the consolidated design. The deltas are documented here so future readers can see *why* each architectural choice exists.

**v2 — Ember's first critique.** The original `CLAUDE.md` sketch had an auto-rehydrating tokenizer (sanitize on the way out, restore on the way back). v2 demoted reversible tokenization to a private, opt-in, whitelist-required, single-use API — the single most dangerous surface in the prior design was a re-identification oracle. v2 also introduced:
- `rule_hit OR classifier_high` block logic (neither layer can unilaterally pass; either can block)
- NFKC + zero-width/bidi/variation-selector strip + homoglyph fold (Cyrillic/Greek/Armenian → Latin)
- Provider-specific key patterns (AWS, Google, GitHub, Slack, Stripe) with prefix anchors
- Two-framing classifier consensus (`max(framing1, framing2)`); disagreement is its own audit event
- Fail-closed default on classifier outage (toggle via `SPEKTRALIA_FAIL_OPEN=1`)

**v3 — OWASP ASI Top 10 compliance pass.** Closed three remaining ASI risks v2 missed:
- ASI-06 (audit integrity) → hash-chained tamper-evident audit, persisted across restarts via `~/.spektralia/audit.state`
- ASI-09 (supply chain) → `pattern_hash`, `model_digest`, `prompt_hash`, pip lockfile with `--require-hashes`, SBOM
- ASI-10 (behavioral monitoring) → rolling anomaly counters with auto-freeze thresholds for classifier_unavailable / framing_disagreement / canary_drift

**v4 — Ember's second-pass blindspot review.** Closed the threat surfaces v2/v3 never examined:
- Ollama trust channel: UDS preferred (S_ISSOCK + owner==EUID + mode 0600 + owner-only parent); TCP fallback pins PID + binary SHA-256 + version
- Filesystem state semantics: `fsync` + atomic rename for `audit.state`; `flock` for freeze file; mode 0600 enforcement
- Memory hygiene for originals: `Secret(bytearray)` with `wipe()` and `__del__`-on-drop; scrubbed `__repr__`/`__str__`; `PR_SET_DUMPABLE=0` at import on Linux
- Detection blindspots: IDN email shadow (IDNA-encoded), opportunistic base64/hex/gzip unwrap → re-scan, PEM body heuristic without header
- Classifier as adversary: canary corpus with random-nonced payloads; drift → auto-freeze
- Operational proof: heartbeat audit emission; `spektralia hook-check`
- Conversation-history leakage (cloud side): documented as out-of-scope for the per-turn gate; `/compact` warning in README
- UX failure modes: mutation-until-pass detector in soft mode; `--explain` flag
- Claude Code hook surface: **`PreToolUse(Task)` is mandatory** (without it a parent agent can launder context into a subagent prompt and bypass `UserPromptSubmit`); default-deny MCP matcher; attachment refusal
- ReDoS: `regex` module with per-call `timeout=100ms`, returns `REGEX_TIMEOUT` sentinel → gate fails closed
- Compliance frame: `docs/COMPLIANCE.md`, `docs/THREATS.md`, README with verbatim disclaimer

**v1 (consolidated, current).** Folds v2+v3+v4 into a single specification — see `SPEC.md`. All architectural decisions below trace to one of the drafts above.

---

## 2. Architecture

```
input
  │
  ▼  normalize (NFKC + strip zero-width/bidi/homoglyphs; offset map back to original)
  ▼  scan      (regex + Luhn/MOD-11 validators + entropy + decoded payloads + IDN shadow)
  ▼  sanitize  (random-suffix typed tokens; no public restore())
  ▼  classify  (Ollama, format=json, two framings, fail-closed)
  ▼  gate      (rule_hit OR classifier_high → block; else pass)
  │
  ▼ sanitized payload → cloud LLM call

Every action produces a hash-chained audit event.
A canary corpus runs at startup and on a schedule; drift auto-freezes the gate.
```

### Module map

```
src/spektralia/
  __init__.py          gate, gate_sync, SensitiveDataError, GateResult, Settings
  config.py            Settings; precedence: kwargs > env > toml > defaults; policy_field markers
  patterns.py          Pattern(label, regex, validator, priority); 100ms ReDoS-safe timeout
  normalize.py         NFKC, strip obfuscation chars, homoglyph fold, offset map, whitespace shadow
  scanner.py           Detection dataclass (label+span only), scan(), span dedupe, IDN shadow
  entropy.py           Shannon entropy at token boundaries, allowlist (UUIDv4/SHA/paths)
  decode.py            base64/hex/gzip unwrap (single level) + re-scan → <LABEL>_ENCODED
  memory_safety.py     Secret(bytearray), wipe(), scrubbed repr, PR_SET_DUMPABLE=0 at import
  sanitizer.py         [REDACTED:LABEL:<6hex>] tokens, private _restore (JSONPath, single-use)
  classifier.py        Ollama format=json, two framings, max-consensus, fail-closed
  ollama_trust.py      UDS preferred; TCP with PID/exe-hash/version pin fallback
  cache.py             LRU(1024) keyed on sha256(sanitized_text || effective_hash)
  canary.py            corpus self-test (in-process + nonced), drift → auto-freeze
  integrity.py         pattern_hash, model_digest, dep lockfile check
  anomaly.py           rolling counters, auto-freeze, freeze file
  heartbeat.py         periodic audit emission
  audit.py             hash-chained, persistent (audit.state with fsync+atomic rename), sinks
  gate.py              orchestration, soft mode, --explain, max_input_chars
  errors.py            SensitiveDataError
  cli.py               versioned subcommands (scan, freeze, audit-verify, hook-check, etc.)

integrations/claude_code_hooks/
  session_start.py     verify-integrity + self-test + hook-check
  user_prompt_submit.py
  pre_tool_use.py      Task, Bash, Write, Edit + default-deny MCP   ← Task hook MANDATORY
  post_tool_use.py     Read, Bash, Grep, Glob, MCP results
  stop.py
  settings.example.json
```

### Key design decisions (from v1 spec)

- **Fail-closed default.** Classifier outage → block, not pass.
- **No public `restore()`.** Tokens are one-way by default; restoration is private, opt-in, JSONPath-scoped, single-use.
- **`rule_hit OR classifier_high` to block.** Neither layer can unilaterally pass; either can block.
- **Two-framing classifier consensus.** `max(framing1, framing2)`; disagreement is its own audit event.
- **Ollama trust.** Prefer UDS with 0600 owner-check; TCP fallback pins PID + binary hash + version.
- **Canary corpus.** Backdoored model / drift → gate auto-freezes.
- **Audit chain persists across restarts.** `~/.spektralia/audit.state` holds the last hash.
- **`PreToolUse(Task)` hook is required.** Without it, a parent agent can launder context into a subagent prompt and bypass `UserPromptSubmit`.
- **What the gate does NOT cover:** contextual PII in prose (NER is v2 roadmap), model outputs, `/compact` summarization (above the API), attachments (refused by default).

---

## 3. Phased implementation plan

The spec is too large to implement in one pass. Four sequential phases; each ends in a green `pytest -q` and a reviewable surface. Phase boundaries are natural commit points.

---

### Phase 1 — Deterministic core ✅ (complete, 109 tests passing)

The synchronous detection pipeline. No network, no audit chain yet. Verifies pattern correctness and sanitizer guarantees in isolation.

**Modules:** `memory_safety` → `normalize` → `patterns` → `entropy` → `decode` → `scanner` → `sanitizer` → `integrity`, with `__init__.py` and `tests/conftest.py` set up first. Implemented TDD-style per module.

**Patterns shipped:** EMAIL (+ IDN shadow), IP_ADDR, CVE, INTERNAL_HOST, CREDIT_CARD (+Luhn), NO_PID (+MOD-11), API_KEY_GENERIC (regex module, 100ms timeout → `REGEX_TIMEOUT`), AWS/Google/GitHub/Slack/Stripe prefixes, JWT (decode header, assert `alg`), PRIVATE_KEY_BLOCK, PRIVATE_KEY_BODY heuristic.

**Tests present:** `test_patterns.py`, `test_normalize.py`, `test_entropy.py`, `test_decode.py`, `test_scanner.py`, `test_sanitizer.py`, `test_no_secret_in_exceptions.py`, `test_config_hash_covers_all_settings.py`, `test_memory_safety.py`, `test_integrity.py`.

**Bugs fixed during Phase 1:**
1. `OBFUSCATION_CHAR` dedupe suppression — fixed via `_ALWAYS_EMIT` in `scanner._dedupe` so audit-visible events are not silenced by overlap with a larger secret span.
2. AWS ASIA key test vector was 19 chars instead of required 20.
3. `REGEX_TIMEOUT` sentinel now explicitly tested with `monkeypatch(_TIMEOUT_MS=0.001)`.
4. IDN email detection — added `_scan_idna_emails()` in `scanner.py` so `alice@münchen.de` is detected via IDNA-encoding shadow.

#### Phase 1 carry-overs — must close before Phase 2 starts

These slipped past the original Phase 1 because the code grew ahead of the spec contract. Address them while Phase 1 modules are still the active surface:

1. **NFKC offset map is incorrect for length-changing codepoints.** `normalize.py` builds the offset map before the NFKC pass; codepoints like `ﬃ` (1 → 3 chars) misalign it, so `_remap_offset` returns wrong original positions and the sanitizer replaces the wrong byte range. Fix by folding length-changing chars in a pre-pass with a per-output-char source-index list, or by making NFKC the first transform and building the offset map against its output. Add a test that scans an NFKC-expanding input containing a secret and asserts the original-text span boundaries are correct.
2. **`tests/corpus/{positive,negative,injection}/` are empty.** Spec §20 requires positive-per-category fixtures, negative bait (UUIDs, SHAs, lorem, version strings), and injection payloads. Seed each directory and have at least one scanner test consume them. The in-process `canary.py` is a separate mechanism (§13.3) and does not satisfy this.
3. **`_restore` is label-based, not JSONPath-based.** Spec §8 requires JSONPath expressions per call site, not global label prefixes. Today `_restore(text, sanitized, unsafe_restore_fields=["EMAIL"])` restores every EMAIL token globally — too coarse for Phase 3 hook restoration. Change to `unsafe_restore_paths: list[str]` (JSONPath against a structured payload). Keep "private, single-use, never exported" invariants.
4. **`PR_SET_DUMPABLE=0` is called in `Gate.__init__`, not at module import.** Spec wants this on Linux at module import time. CLI paths that use the scanner without instantiating a gate (`spektralia scan-config`, `spektralia verify-integrity`) currently handle sensitive data with core dumps enabled. Move into `memory_safety.py` top-level (Linux-guarded, swallow failures).

#### Phase 1 exit criteria

- `pytest -q` green ✅
- `python -c "from spektralia.scanner import scan; print(scan('alice@example.com 4111111111111111'))"` shows two detections
- `repr(secret)` never leaks value
- `Settings().config_hash()` stable across runs
- `pattern_hash` deterministic
- Corpus directories non-empty; at least one scanner test consumes them ⚠️ (carry-over #2)
- NFKC-expanding sanitization round-trip test passes ⚠️ (carry-over #1)
- `PR_SET_DUMPABLE` invoked on scanner-only import ⚠️ (carry-over #4)
- `_restore` accepts `unsafe_restore_paths` ⚠️ (carry-over #3)

---

### Phase 2 — Audit, anomaly, classifier, cache, gate

The async surface and the hash-chain backbone. **Modules already exist in-tree** but are missing required tests and carry active correctness bugs.

**Modules:**
- `audit.py` — hash-chained records (seq, prev_hash, record_hash, times, action, labels, categories, confidence, hashes); `~/.spektralia/audit.state` persistence with `fsync`; `AuditSink` abstraction with `JournaldSink`/`SyslogSink`/`AppendOnlyFileSink`/`StdoutSink`; detection-based default; `audit-verify` logic
- `anomaly.py` — rolling counters over `window_seconds`, auto-freeze thresholds for classifier_unavailable / disagreement / canary_drift; override-rate audit-only
- `cache.py` — LRU(1024) keyed on `sha256(sanitized_text || config_hash || pattern_hash || model_digest || prompt_hash)`; invalidation hooks for config/digest/pattern/prompt change, freeze/unfreeze, canary drift, self-test fail
- `ollama_trust.py` — UDS preferred (`lstat` S_ISSOCK + owner==EUID + mode 0600 + owner-only parent); TCP fallback with PID + binary sha256 + version pin; model-digest pinned references
- `classifier.py` — httpx call to Ollama, `format:"json"`, `<input>…</input>` framing with escaping, two-framing consensus (`max`), `framing_disagreement` audit, enum-bounded categories, fail-closed
- `canary.py` + `src/spektralia/canary/corpus/` — known-bad / known-safe / random-nonced payloads; drift → freeze
- `heartbeat.py` — periodic emission
- `gate.py` — `async gate(text, settings)` orchestration; `rule_hit OR classifier_high` block logic; soft mode + mutation-until-pass; `gate_sync` wrapper; `max_input_chars` deterministic block; `GateResult` exposes labels only
- `__init__.py` — adds `gate`, `gate_sync`, `GateResult`

**Tests required:** `test_audit_chain.py` ✅, `test_audit_no_values.py` ✅, `test_anomaly.py` ✅, `test_cache.py` ✅, `test_canary.py` ✅, `test_classifier.py` (respx-mocked) ✅, **`test_ollama_trust.py` ⚠️ (missing)**, **`test_gate.py` ⚠️ (missing)**, `test_integrity.py` ✅.

#### Active correctness bugs to fix in Phase 2

These are real bugs in code already on disk. Fix them as part of Phase 2's normal scope:

5. **Cache key uses raw text, not sanitized text.** Spec §15 requires `sha256(sanitized_text || config_hash)`. `gate.py:150` currently passes the original `text` to `LRUCache.make_key`. A future sanitization-behavior change could let a cached "pass" verdict escape against a payload that should now block. Move the cache lookup to **after** `sanitize()`, keyed on `result.text`.
6. **`config_hash` omits `pattern_hash`, `model_digest`, and `prompt_hash`.** Spec §15 requires all three in the cache key. `Settings.config_hash()` only iterates dataclass fields; pattern/model/prompt hashes live elsewhere and are never folded in. Edit a regex → cache does not invalidate. Two gates with different pattern tables share cached results. Either extend `config_hash()` to mix the three when called by the `Gate`, or compute an effective cache key `sha256(sanitized_text || config_hash || pattern_hash || model_digest || prompt_hash)`. Add tests that mutate each hash and assert cache miss.
7. **Cache does not invalidate on freeze/unfreeze or self-test failure.** Spec §15's invalidation list includes both. Today only canary drift calls `invalidate_all()`. A "pass" cached before a freeze can be served on the first call after unfreeze. Wire `freeze()`, `unfreeze()`, and self-test failure into `LRUCache.invalidate_all()`; test the round-trip explicitly.
8. **`SyslogSink` not implemented.** Spec §13.1 lists four sinks; only journald/file/stdout exist. Add the syslog sink; route `_choose_sink` through it on journald failure before the file fallback.
9. **`test_gate.py` and `test_ollama_trust.py` are mandatory Phase 2 deliverables.** `gate.py` (block decision, soft-mode mutation detector, freeze interaction, anomaly auto-freeze) and `ollama_trust.py` (UDS owner/mode rejection, TCP PID-pin change → freeze, model digest mismatch → freeze) carry the security-critical contracts of Phase 2 and must not ship without tests.

#### Phase 2 exit criteria

- `pytest -q` green with respx-mocked Ollama
- Two-framing consensus + injection corpus does not flip verdict
- Kill-and-restart simulation in `test_audit_chain.py` shows chain reanchors via `audit.state`
- Canary drift triggers freeze (auto), surfacing through `spektralia stats`
- **Cache-invalidation matrix test passes** — pattern_hash, model_digest, prompt_hash, freeze, unfreeze, canary drift, and self-test fail each produce a cache miss
- **`test_gate.py` and `test_ollama_trust.py` green** (mandatory; not optional)
- `SyslogSink` exists and is reachable through `_choose_sink` fallback

---

### Phase 3 — CLI + Claude Code hooks ✅ (complete, 215 tests passing; e2e verified 2026-06-25)

- `cli.py` — versioned subcommand surface from spec §17 (`scan`, `scan --explain`, `check-ollama`, `verify-integrity`, `verify-installed`, `self-test`, `stats`, `freeze`/`unfreeze`, `audit-verify`, `audit-rotate`, `audit-purge`, `scan-config`, `hook-check`)
- `integrations/claude_code_hooks/{session_start,user_prompt_submit,pre_tool_use,post_tool_use,stop}.py`
- `settings.example.json` with per-hook strict vs fast mode mapping
- Default-deny MCP matcher; attachment refusal; hook crash → block
- **`PreToolUse(Task)` hook is mandatory** — without it, subagent prompts launder context past `UserPromptSubmit`

**Exit criteria:** ✅ Live e2e verified 2026-06-25 against real Claude Code + `llama3.1:8b`: `sk_live_*` credential blocked at `UserPromptSubmit`; Agent prompt with email blocked; Bash prompt with email blocked; `spektralia self-test` green.

---

### Phase 4 — Supply chain + docs + CI ✅ (complete, PR #3)

- ✅ `requirements.lock` via `pip-compile --generate-hashes` (pre-existing)
- ✅ `make sbom` target + committed `SBOM.json` (reproducible; strips `file://` via Python post-process)
- ✅ `docs/COMPLIANCE.md`, `docs/THREATS.md`
- ✅ README with verbatim disclaimer paragraph from spec §13.5
- ✅ CI: `verify-installed` gate, per-hook latency budgets (`ci.yml`, `latency.yml`)
- ✅ CI: nightly ReDoS fuzz (`redos-fuzz.yml`) — pure-Python timeout assertion approach (`recheck` unavailable on PyPI; `regex` module's 100 ms guard verified directly)
- ✅ `scripts/redos_fuzz.py` — 16 patterns, exit 1 if any call exceeds 500 ms wall-clock
- ✅ `scripts/latency_bench.py` — p95 per hook vs spec budgets (UMP ≤500 ms, PTU ≤300 ms, PTOU ≤200 ms)

**Exit criteria:**
- ✅ `make sbom` regenerates without diff churn
- ✅ `pip install --require-hashes -r requirements.lock` succeeds in clean venv
- ✅ Nightly ReDoS fuzz dry-run: all 16 patterns complete within 500 ms, exit 0

---

## 4. Reusable code and dependencies

- `src/spektralia/config.py` — already has `Settings` + `config_hash` + `_non_policy` and a `policy_field` marker — keep as-is; `test_config_hash_covers_all_settings.py` exercises it
- `src/spektralia/errors.py` — `SensitiveDataError` aligned with spec §13.5's actionable block-reason format; reuse unchanged
- Python stdlib: `unicodedata` (NFKC), `hashlib`, `secrets` (token suffixes), `base64`, `binascii`, `gzip`, `prctl` via `ctypes` for `PR_SET_DUMPABLE`, `idna` via str.encode for IDN shadow
- Third party (pinned in `pyproject.toml`): `httpx`, `regex` (ReDoS-safe with `timeout=`), `keyring`; dev: `pytest`, `pytest-asyncio`, `respx`, `cyclonedx-bom`
- Ollama: `ollama pull llama3.1:8b`

---

## 5. Threat model summary

**In scope:** preventing PII / credentials / internal identifiers from being included in cloud LLM payloads; tampering with the gate itself; other local processes on the same UID (TCP-port hijack, dropped freeze file, `/proc/$pid/mem`); classifier model as adversary (backdoor, registry compromise); cloud LLM conversation history as leak channel above the gate; user as adversary-of-themselves (alarm fatigue, mutation-until-pass).

**Out of scope:** network MITM on the Anthropic API; kernel-level local attackers / root or `CAP_SYS_PTRACE`; side-channels across tenants; attacks on the Ollama binary itself.

**Posture:** fail-closed throughout. If any component cannot make a confident "safe" decision, block.

---

## 6. Verification commands

```bash
# Install (dev)
pip install -e .[dev]

# Run tests
pytest -q

# CLI (Phase 3)
spektralia scan                   # stdin → sanitized stdout; exit 2 on block
spektralia scan --explain         # show which detectors ran and why
spektralia self-test              # run canary corpus against live classifier
spektralia verify-integrity       # print pattern/model/prompt hashes
spektralia verify-installed       # check pip hashes against requirements.lock
spektralia stats                  # rolling counters + freeze state
spektralia freeze / unfreeze
spektralia audit-verify <path>
spektralia scan-config            # lint CLAUDE.md files for sensitive content
spektralia hook-check             # assert Claude Code hooks installed correctly
spektralia check-ollama           # ping configured Ollama endpoint

# SBOM (Phase 4)
make sbom                         # regenerates SBOM.json via cyclonedx-py
```

---

## 8. v2 roadmap

Items deferred from v1 scope. Add to this list whenever a task surfaces a candidate; don't wait.

- **Contextual PII / NER** — names, addresses, free-text identifiers not capturable by regex. Requires a local NER model (spaCy or similar). Currently documented as out-of-scope in spec §13.5.
- **Cryptographic hook identity (stronger form)** — current HMAC-in-keyring approach makes substitution *auditable*; a future version could use an Ed25519 key pair so the hook can *prove* identity to a verifier without relying on keyring availability.
- **Hook signing / binary integrity** — verify that the hook scripts themselves haven't been tampered with (hash of hook files at install time, checked at SessionStart against a stored manifest).
- **Gating model outputs / assistant turns** — currently out of scope; prose response stream is the wrong surface for v1 but worth revisiting once NER lands.
- **`pip install --require-hashes` enforcement at install time** — Phase 4 exit criteria mention this; wire it into the install docs and CI once Phase 4 closes.
- **ReDoS nightly fuzz** — Phase 4 CI item; add as a scheduled GitHub Actions job.
- **Log raw model response on empty categories** — when the classifier returns `sensitive=True, confidence=1.0, categories=[]`, the fail-closed defaults mask whether the model returned a bad response or an empty-but-valid one. Log the raw model output (redacted) at DEBUG level so false positives are diagnosable without rerunning with a debugger.
- **Automated hook setup (`spektralia install-hooks`)** — ✅ implemented (`src/spektralia/install.py`). Locates the repo root, renders the five hook commands from `settings.example.json`, merges them into `.claude/settings.json` (project, default) or `~/.claude/settings.json` (`--global`) without clobbering unrelated keys, writes mode 0600, and self-verifies via `hook-check`.
- **Cross-layer sandbox preflight (`spektralia check-sandbox`)** — ✅ implemented. Asserts the configured execution-plane sandbox (`fence` or `cplt`) is on `PATH`, with optional config-hash pinning (detect-only by default); wired into the `SessionStart` preflight and `none` by default so existing installs are unaffected. Realizes the [ENDPOINT_STACK.md cross-layer-integrity item](ENDPOINT_STACK.md); see [SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md) for the Fence-vs-[cplt](https://github.com/navikt/cplt) comparison.
- **Control-plane preflight (`spektralia check-prempti`)** — ✅ implemented (`src/spektralia/prempti.py`). The control-plane analog of `check-sandbox`: asserts `premptictl` is on `PATH`, that `prempti_socket` (if set) is a live socket, and an optional detect-only config-hash pin; wired into `SessionStart`; `none` by default. Completes the cross-layer-integrity item for the control plane.
- **Deployable endpoint bundle (`endpoint/`)** — ✅ added. Ships the cplt execution-plane config (repo-root `.cplt.toml` + `endpoint/cplt-global-config.toml`), the activated Spektralia config (`endpoint/spektralia.endpoint.toml`), sample Prempti/Falco rules (`endpoint/prempti/spektralia.rules.yaml`), a launcher (`scripts/run-claude-sandboxed.sh`, "agent inside cplt"), and a bring-up README. Targets cplt per [SANDBOX_ALTERNATIVES.md](SANDBOX_ALTERNATIVES.md).

---

## 9. v3 roadmap

Items deferred beyond v2 scope.

- **Quickstart setup script** — a `scripts/setup.sh` (or `spektralia setup` CLI subcommand) that installs the venv, pulls the Ollama model, and wires Claude Code hooks in one step for end-users. `--dev` flag additionally installs dev dependencies, seeds the canary corpus, runs the full test suite, and verifies hook-check, so a developer has a fully exercised environment after a single command.

---

## 7. Where to find what

- **Full 22-chapter implementation spec** (exact schemas, signatures, behaviour): `SPEC.md`
- **Design rationale** (why each decision was made — Ember critiques, OWASP ASI gap analysis, Ollama trust reasoning): `RATIONALE.md`
- **This file (PLAN.md):** phased plan, current status, bugs, and carry-overs. Update as phases close.

### Hook known issues — **MUST FIX BEFORE PROD** (found 2026-06-24, §3.19)

See `docs/hook-exceptions-v2.md` for full detail. Summary of five items that are v2 work but are prod-release blockers:

1. Self-scan: Write/Edit hooks scan own source files and trip false positives
2. Empty categories pattern from classifier on benign content (`categories=[]`)
3. UnboundLocalError in post_tool_use import block when venv unavailable
4. Wrong JSON output shape in all three hook scripts (fixed in session; needs contract test)
5. Wrong tool name for subagent spawn (`"Task"` was `"Agent"`; fixed in session; needs regression test)
