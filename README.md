# Spektralia

A local pre-cloud sensitivity gate. Normalizes and scans input for PII, credentials, and internal identifiers before any cloud LLM call; classifies residual risk locally via Ollama; blocks or passes the sanitized payload.

> **Disclaimer:** This tool is a best-effort gate, not a security guarantee. It will not catch all sensitive data. Do not rely on it as a sole control for data classified above the threat model it addresses (see `PLAN.md §2`). Sensitive work should be done in fresh sessions, not through `/compact`.

```
input
  │
  ▼  normalize   (NFKC + strip zero-width/bidi/homoglyphs)
  ▼  scan        (regex + Luhn/MOD-11 + entropy + decoded payloads + IDN shadow)
  ▼  sanitize    (random-suffix typed tokens; no public restore())
  ▼  classify    (Ollama, format=json, two framings, fail-closed)
  ▼  gate        (rule_hit OR classifier_high → block; else pass)
  │
  ▼  sanitized payload → cloud LLM call
```

Every action produces a hash-chained audit event. A canary corpus runs at startup and on schedule; drift auto-freezes the gate.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
ollama pull llama3.1:8b
pytest -q
spektralia scan            # stdin → sanitized stdout; exit 2 on block
spektralia self-test       # run canary corpus against live classifier
spektralia hook-check      # assert Claude Code hooks are installed correctly
```

### Starting Ollama

```bash
ollama serve
```

Ollama listens on `http://127.0.0.1:11434` by default. Spektralia connects via TCP and pins the remote PID and binary hash on first connection. UDS support depends on Ollama exposing a socket — check your Ollama version's documentation.

Configure spektralia to use a non-default endpoint via env var or TOML:

```bash
# env var
export SPEKTRALIA_OLLAMA_URL="http://192.168.1.10:11434"   # remote or non-default TCP
export SPEKTRALIA_OLLAMA_SOCKET="/path/to/ollama.sock"      # UDS (takes precedence over URL, if Ollama exposes one)
```

```toml
# ~/.spektralia/config.toml or ./spektralia.toml
[spektralia]
ollama_url    = "http://192.168.1.10:11434"
ollama_model  = "llama3.1:8b"
```

### Classifier sensitivity threshold

The gate blocks when the classifier returns `confidence >= sensitivity_threshold` (default `0.7`). Raise it to reduce false positives from the model:

```bash
# env var (one-off)
SPEKTRALIA_SENSITIVITY_THRESHOLD=0.9 spektralia scan

# persistent — env var in shell profile
export SPEKTRALIA_SENSITIVITY_THRESHOLD=0.9

# persistent — TOML config
```

```toml
# ~/.spektralia/config.toml or ./spektralia.toml
[spektralia]
sensitivity_threshold = 0.9
```

Threshold range: `0.0` (block on any classifier signal) to `1.0` (only block at maximum confidence). The rule-based scanner always blocks regardless of this value — the threshold only governs classifier-driven blocks.

---

## Key decisions, by phase

### Phase 1 — Deterministic core (spec §§4–8, §10, §12)

**`rule_hit OR classifier_high` to block (§14)**
Either layer blocks; neither can unilaterally pass. This is the core security invariant — the classifier is a second signal, not an override.

**No public `restore()` (§8)**
Tokens are one-way by default. Restoration is private (`_restore`), opt-in, requires a per-call JSONPath allowlist, and is single-use (the token map entry is deleted after). Re-identification is not an automatic reverse operation. Rationale: the prior design had a public restore API which acted as a re-identification oracle for any caller who could construct a `Sanitized` object.

**`Secret(bytearray)` with `wipe()` (§10)**
Original values are wrapped in `Secret` immediately on detection. `wipe()` zeroes the backing `bytearray`; `__repr__`/`__str__` never reveal the value; `__del__` calls `wipe()` automatically. `PR_SET_DUMPABLE=0` is set at `memory_safety` import time on Linux so core dumps do not capture secrets from any process that imports the scanner.

**NFKC + homoglyph fold before scan (§5)**
Normalization runs before pattern matching. Zero-width chars, bidi overrides, and variation selectors each produce an `OBFUSCATION_CHAR` detection (so obfuscation attempts are themselves audit events). The offset map traces every character back to its original position so sanitization replaces the right bytes in the original text. Cyrillic, Greek, and Armenian lookalikes are folded to Latin equivalents before the scan.

**IDN email shadow (§4)**
The EMAIL pattern regex is ASCII-only. For inputs with non-ASCII email domains (`alice@münchen.de`), `scanner._scan_idna_emails()` IDNA-encodes the domain to punycode and validates the result matches the EMAIL pattern. This runs in parallel with the main scan; detections use original-text offsets.

**`REGEX_TIMEOUT` sentinel → fail closed (§4)**
The `regex` module's `timeout=` parameter fires `TimeoutError` when a pattern exceeds 100ms CPU on a given input. `match_pattern()` catches this and returns `(-1, -1, "REGEX_TIMEOUT")`. The scanner converts this into a `Detection(label="REGEX_TIMEOUT")` that the gate treats as a "could not complete" → block signal, not a "no match" → pass signal.

**`OBFUSCATION_CHAR` exempt from deduplication (§5)**
The span deduplicator keeps only the longest non-overlapping spans. `OBFUSCATION_CHAR` detections are exempted via `_ALWAYS_EMIT` — they represent audit events, not secret spans, and must be preserved even when they overlap a larger detection.

**Base64/hex/gzip decode before scan (§7)**
A single level of encoding is unwrapped and re-scanned. Detections on the decoded payload are reported as `<LABEL>_ENCODED` against the outer span in the original text. Only one unwrap level is performed to avoid recursive-decode DoS.

**`pattern_hash` covers the full pattern table (§12)**
`integrity.compute_pattern_hash()` serializes every `Pattern` (label, regex, validator source, priority) and hashes the result. If a pattern is modified — including silently by a supply-chain attack — the hash changes. It is folded into the cache key so a pattern change invalidates all cached verdicts.

---

### Phase 2 — Audit, classifier, cache, gate (spec §§9, §§11–15)

**Two-framing classifier consensus (§9)**
The Ollama classifier is called twice with different prompt framings (one asks "what is sensitive here?", one asks "is there anything safe to redact?"). `max(confidence1, confidence2)` is the final score. When the two framings disagree beyond a threshold, a `framing_disagreement` event is emitted to the audit log — disagreement is evidence of ambiguity, not evidence of safety.

**Ollama trust: UDS preferred, TCP pinned (§11)**
The UDS socket is validated with `lstat` before every connection: `S_ISSOCK`, `owner==EUID`, `mode 0600`, parent directory owner-only. TCP fallback is permitted only when UDS is unavailable, and it pins the remote process's PID, binary SHA-256 (`/proc/$pid/exe`), and Ollama version string at first connection. Any change to PID, binary hash, or version string triggers an immediate gate freeze. This closes the threat of another local process pre-binding `localhost:11434` to intercept or manipulate classifier calls.

**Audit chain persists across restarts (§13.1)**
`~/.spektralia/audit.state` stores the last record hash. New sessions read this file and anchor their first record to it, maintaining the chain. Records are written with `fsync` + atomic rename. The state file is mode 0600. `audit-verify` walks the full chain and reports the first broken link.

**Canary corpus → auto-freeze on drift (§13.3)**
A set of known-bad, known-safe, and random-nonced payloads runs at startup and on a heartbeat schedule. If the classifier starts returning wrong answers (backdoored model, model swap, weights drift), the gate auto-freezes and emits a `canary_drift` audit event. The freeze must be explicitly lifted with `spektralia unfreeze`.

**Cache keyed on sanitized text + effective hash (§15)**
The LRU cache is keyed on `sha256(sanitized_text || config_hash || pattern_hash || model_digest || prompt_hash)`. The lookup happens **after** `sanitize()`, not on the original text. This means: (1) the raw secret is never the cache key; (2) changing any of the five inputs produces a cache miss. Cache is invalidated entirely on freeze, unfreeze, canary drift, or self-test failure.

**Anomaly counters + auto-freeze (§13.2)**
Rolling counters track `classifier_unavailable`, `framing_disagreement`, and `canary_drift` events over a configurable window. When any counter exceeds its threshold, the gate auto-freezes and refuses all traffic until manually unfrozen. Override events (user manually unblocking a detection) are counted separately and emit audit events but do not auto-freeze by themselves.

---

### Phase 3 — CLI + Claude Code hooks (spec §§17–18)

**`PreToolUse(Task)` hook is mandatory (§18)**
Without the `Task` hook, a parent agent can construct a subagent with a prompt that carries the original (unsanitized) context, bypassing `UserPromptSubmit`. The `Task` hook intercepts the `prompt` field of every `Task` tool call and runs it through the full gate before the subagent is launched.

**Default-deny MCP matcher (§18)**
The `PreToolUse` hook applies a default-deny policy to MCP tool calls: any MCP tool not on an explicit allowlist is blocked with `SensitiveDataError`. This prevents unknown MCP servers from exfiltrating data that has been sanitized out of the main prompt.

**Attachment refusal (§18)**
File attachments in Claude Code prompts are refused by default. `--allow-attachments` opts in explicitly. This prevents binary or document content from entering the pipeline without going through the full scan.

**Hook crash → block (§18)**
If any hook process exits non-zero or raises an unhandled exception, the Claude Code harness treats it as a block signal. Hooks are never allowed to fail silently.

---

### Phase 4 — Supply chain + compliance (spec §§12, §19)

**`pip-compile --generate-hashes` (§12)**
`requirements.lock` is generated with hash pinning. `spektralia verify-installed` checks every installed package against the lock file at startup. A mismatch triggers a gate freeze.

**`pattern_hash` + `model_digest` + `prompt_hash` (§12)**
Three integrity signals are emitted at startup via `spektralia verify-integrity`: the SHA-256 of the compiled pattern table, the SHA-256 of the Ollama model weights blob, and the SHA-256 of the two classifier prompt templates. All three are folded into the effective cache key. A silent swap of any of the three makes itself visible.

**`docs/COMPLIANCE.md` and `docs/THREATS.md` (§19)**
Compliance documentation maps each gate component to its OWASP ASI Top 10 risk. The threat doc enumerates the in-scope attacker models and documents exactly what this gate does and does not protect against.

---

## What this gate does NOT cover

- **Contextual PII in prose** — names, addresses, free-text NER. Regex cannot reliably detect these; v2 roadmap item.
- **Model outputs / assistant turns** — gating the response stream is the wrong surface for this problem.
- **`/compact` summarization** — this happens above the API boundary. Start fresh sessions for sensitive work.
- **Attachments** — refused by default; `--allow-attachments` to opt in.
- **Network MITM on the Anthropic API** — out of threat model scope.
- **Kernel-level local attackers** — root or `CAP_SYS_PTRACE`; out of scope.

---

## Troubleshooting

### Classifier times out (`classifier_unavailable: timed out`)

`spektralia check-ollama` only pings `/api/version` — it does not run inference. The model may not yet be loaded into memory, causing the first classify call to exceed the default 10-second timeout. Fix:

```bash
# Warm up the model before running spektralia
ollama run llama3.1:8b "ping" --nowordwrap

# Or raise the timeout for a single invocation
SPEKTRALIA_CLASSIFIER_TIMEOUT_SECONDS=60 spektralia scan
```

The gate still blocks on a rule hit even when the classifier is unavailable — `classifier_unavailable` in the block reason is a secondary signal, not the primary cause of the block.

### Classifier false-positives on benign input (`classifier(1.00, [])`)

`llama3.1:8b` may classify short or ambiguous benign text as sensitive with `confidence: 1.0` and no categories (`[]`). This happens because the classifier defaults to fail-closed when the model's JSON response lacks specific category signals. The `sensitivity_threshold` (default `0.7`) applies — `confidence >= threshold` blocks.

Options:

```bash
# Use a longer, unambiguous sentence to test
echo "The weather today is sunny and warm." | spektralia scan

# Raise the threshold to reduce false positives
SPEKTRALIA_SENSITIVITY_THRESHOLD=0.9 spektralia scan

# Skip classifier-driven blocks entirely (fail-open mode, not recommended for production)
SPEKTRALIA_FAIL_OPEN=1 spektralia scan
```

Rule-based blocks (email, credit card, API keys, etc.) are always enforced regardless of `SPEKTRALIA_FAIL_OPEN` or the sensitivity threshold.

---

## Reference

- `PLAN.md` — consolidated phased plan with current status, bugs, and carry-overs
- `SPEC.md` — full 22-chapter implementation spec (exact schemas, signatures, behaviour)
- `RATIONALE.md` — full design arguments (Ember critiques, OWASP ASI gap analysis, Ollama trust reasoning)
- `CLAUDE.md` — file layout, commands, dependency list
