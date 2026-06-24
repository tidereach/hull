# Spektralia v4 — Hardening overlay (Ember blindspot pass)

## Context

v2 produced a self-contained implementation plan. v3 layered OWASP ASI hardening (supply-chain integrity, anomaly counters, hash-chained audit). v4 closes the threat surfaces Ember's second-pass review surfaced — assumptions the prior drafts never examined: trust in `localhost:11434`, filesystem semantics around the gate's own state files, secret lifetimes in process memory, detection blindspots beyond regex/entropy/classifier, the classifier itself as adversary, proof-of-operation, conversation-history leakage above the gate, UX failure modes that cause real-world bypass, the broader Claude Code hook surface (notably `Task` for subagents), confirmed ReDoS, and the entirely-missing compliance frame.

v4 is an **overlay on v2+v3** — everything from those documents carries forward unchanged unless explicitly revised here.

## Revised threat model (delta from v3)

Newly in-scope:
- **Other local processes/users on the same UID or host.** Includes processes that can bind a TCP port before Ollama does, drop files in `~/.spektralia/`, or read process memory via `/proc/$pid/mem`.
- **The classifier model itself as adversary** (backdoored weights, registry compromise).
- **The cloud LLM's growing conversation history** as a leak channel that exists *above* the per-turn gate.
- **The user as adversary-of-themselves** — alarm fatigue, false sense of security, mutation-until-pass.

Still out of scope (explicit): network MITM on the Anthropic API, kernel-level local attacks, malicious local processes with root/CAP_SYS_PTRACE.

## Module additions / changes

```
src/spektralia/
├── ollama_trust.py        (NEW — channel hardening; UDS/PID/exe pinning)
├── normalize.py           (CHANGED — strip zero-width, bidi overrides, variation selectors; expanded homoglyph map)
├── decode.py              (NEW — opportunistic base64/hex/gzip unwrap + re-scan)
├── canary.py              (NEW — startup + scheduled self-test corpus)
├── heartbeat.py           (NEW — periodic audit emission)
├── memory_safety.py       (NEW — bytearray-backed Secret type, zeroize, dumpable=0)
├── audit.py               (CHANGED — persistent chain across restarts; sink abstraction)
├── anomaly.py             (CHANGED — freeze on canary drift, override-rate counter)
├── classifier.py          (CHANGED — single-framing fast mode toggle, min/max disagreement signal)
├── patterns.py            (CHANGED — API_KEY_GENERIC ReDoS-safe rewrite; uses `regex` module with timeout)
├── gate.py                (CHANGED — soft-mode override path with audit; --explain; integration of all above)
└── cli.py                 (CHANGED — scan-config, self-test, hook-check subcommands; versioned CLI surface)

integrations/claude_code_hooks/
├── session_start.py       (NEW)
├── pre_tool_use.py        (CHANGED — Task added to matchers; default-deny MCP policy)
├── stop.py                (NEW — final audit roll-up)
└── settings.example.json  (NEW — canonical hook config integrators copy from)

docs/
├── README.md              (CHANGED — limits-disclaimer in opening paragraph)
├── COMPLIANCE.md          (NEW — GDPR, PCI-DSS, HIPAA framing)
└── THREATS.md             (NEW — full threat model from v3 + v4 deltas in one place)
```

## 1. Ollama trust channel (`ollama_trust.py`) — §1 of the punch list

The biggest unaudited assumption in v1–v3. A local attacker who binds 11434 before Ollama does can return permissive verdicts and a valid-looking `/api/tags`.

- **Preferred transport: Unix domain socket.** When `Settings.ollama_socket` is set, the gate uses an HTTP-over-UDS transport. Before first use, `os.lstat()` the socket path and require:
  - It is a socket (`S_ISSOCK`).
  - Owner == process EUID.
  - Mode == 0600 (group/other have no access).
  - Parent directory is owner-only.

  Any mismatch → fail-closed at startup with category `"ollama_socket_untrusted"`.

- **Fallback: TCP with process pinning.** When TCP is used (current default), on first successful contact the gate records:
  - The listening process PID (looked up via `/proc/net/tcp` + `/proc/$pid/exe` realpath on Linux; `lsof -i` parsing on macOS).
  - The SHA-256 of the listening binary.
  - The Ollama version string from `/api/version`.

  On subsequent calls, if the listening PID has changed OR the binary hash differs OR the version differs, the gate freezes (category `"ollama_identity_changed"`). The pin is per-process and re-established on restart.

- **Out-of-band shared header (optional).** `Settings.ollama_auth_header` sends `Authorization: Bearer <token>` on every call. Ollama supports custom headers via reverse proxy (nginx in front of UDS, for example). If set, gate refuses to proceed without it.

- **Model swap detection.** Every classifier call sends `model: "name@sha256:<digest>"` (Ollama supports digest-pinned model references). If Ollama rejects ("model digest mismatch"), gate freezes with category `"model_swap_detected"` — does not silently fall back to the new digest.

- **Container/shared-socket warning.** Gate detects whether it is running in a container with a bind-mounted host socket (heuristic: socket exists but parent dir is owned by a different UID space) and emits a one-time audit event `ollama_shared_socket_warning` plus a stderr warning. Documented as configuration recommendation: dedicated Ollama per container/tenant.

- **Telemetry-disabled assertion.** On first call, gate checks Ollama's config for telemetry status (`/api/version` + known env vars). If telemetry-enabled cannot be ruled out, emit `ollama_telemetry_status_unknown` audit event and require an explicit `Settings.ollama_telemetry_accepted=True` to proceed.

## 2. Filesystem state semantics (`audit.py`, `anomaly.py` changes) — §2

- **`~/.spektralia/` enforced 0700 / owner-only / no symlinks in path.** At startup, walk the path with `os.lstat()`; refuse to start if any segment is symlinked, group/other-readable, or owned by a different UID. Same enforcement for any configured config TOML, lock files, and audit file.

- **`FREEZE` file checked via `lstat` only.** Never follows symlinks. Must be `S_ISREG`, mode 0600, owner == EUID. Stale-or-suspicious freeze files (any of those conditions failing) are treated as an active freeze AND audited as `freeze_file_anomalous`.

- **Pattern TOML must be inside `~/.spektralia/` and 0600.** Reject paths outside the trust directory. Optional HMAC verification against a key stored in OS keyring (`keyring` library); when configured, unsigned TOML is refused.

- **Audit sink abstraction.** `audit.py` exposes `AuditSink` interface with concrete implementations:
  - `JournaldSink` (preferred; uses `systemd.journal.send` — append-only by design).
  - `SyslogSink`.
  - `AppendOnlyFileSink` (opens with `O_APPEND | O_CREAT`, refuses if file is writable by anyone but owner, refuses if mode permits `unlink`-style replacement on the parent directory).
  - `StdoutSink` (dev only; emits a warning).

  Default sink chosen by detection: journald > syslog > append-only-file. The "hash chain" of v3 becomes meaningful only when paired with append-only storage; sink choice is logged at startup.

- **Persistent audit chain across restarts (promoted from v3 "future" to v4-required).** The last `record_hash` is written to `~/.spektralia/audit.state` on every flush (and `fsync`-ed). On startup, the new chain's GENESIS is replaced with that hash; first record's `prev_hash` equals last-shutdown record's hash. Mitigates the "crash-and-restart-resets-chain" bypass. `audit-verify` walks across the boundary and reports if the state file was tampered with.

- **Lockfile/SBOM drift check.** `spektralia verify-installed` compares `pip freeze --all` with hashes against `requirements.lock`. Non-zero exit on drift. Documented to run in CI and in `SessionStart` hook.

## 3. Memory hygiene for originals (`memory_safety.py`) — §3

- **`Secret` type wrapping `bytearray`.** All detected original values are immediately moved out of the input `str` into `Secret(bytearray(value.encode("utf-8")))`. Token map holds `Secret`, not `str`. `Secret.__del__` (and an explicit `wipe()`) overwrite the buffer with zeros before drop. `Secret.__repr__` returns `"<Secret:LABEL:redacted>"` regardless of context — survives logging, exception traceback formatting, `repr()` in REPL.

- **`PR_SET_DUMPABLE=0` on Linux at startup.** Refuses core dumps for the gate process. Documented behavior on macOS/Windows (no equivalent, documented as gap).

- **Optional `mlock()` of the `Secret` buffers** when `Settings.mlock_secrets=True`. Off by default (requires `RLIMIT_MEMLOCK`), recommended in deployment docs.

- **Exception message audit.** A test (`test_no_secret_in_exceptions.py`) constructs every exception path the gate can raise on a known-secret input and asserts the original value appears nowhere in `str(exc)`, `repr(exc)`, `exc.__cause__`, or `traceback.format_exc()`. Lint rule: no f-string formatting of untrusted input into exception messages.

- **Faulthandler / crash reporters.** Documentation explicitly tells integrators to disable `faulthandler` (or wrap with a hook that wipes Secrets before signal handler runs) and to not register Sentry/Bugsnag breadcrumbs containing prompt content.

## 4. Detection blindspots — §4

### 4a. `normalize.py` additions
Strip before scan, after NFKC:
- Zero-width characters: `​ ‌ ‍ ⁠ ﻿ ᠎`.
- Bidi overrides: `‪-‮ ⁦-⁩ ؜`.
- Variation selectors: `︀-️ 0-F`.
- Tag characters used in steganography: `0-F`.

Each stripped character contributes a `Detection(label="OBFUSCATION_CHAR", ...)` so removal is visible in audit, not silent.

Expanded homoglyph map: add Greek, Armenian, Cherokee, and Mathematical Alphanumeric (mostly handled by NFKC but verify per-codepoint test exists), plus full-width Latin.

### 4b. Line-wrap shadow scan
Sanitizer constructs a whitespace-collapsed shadow string (`re.sub(r"\s+", "", text)`) with an index map back to original offsets. Detectors run on **both** the original and the shadow. A credit card written as `4111\n1111-1111-1111` is now caught; redaction applies to the original span. Tested explicitly.

### 4c. `decode.py` — opportunistic unwrap
For tokens that look like base64 (length ≥ 40, valid charset, `=` padding) OR hex (length ≥ 64, even length) OR gzip-magic (`\x1f\x8b`):
- Decode once.
- Re-scan the decoded bytes (as UTF-8 with `errors="replace"`).
- Any detection in the decoded form yields a `Detection(label="<LABEL>_ENCODED", ...)` against the *outer* token span.

Documented limit: nested encodings not chased.

### 4d. PEM-body heuristic
`scan_pem_body(text)`: contiguous block of ≥ 10 base64-formatted lines of width 60–76 with no English vocabulary words → `Detection(label="PRIVATE_KEY_BODY", ...)`. Catches bodies pasted without `-----BEGIN-----` headers.

### 4e. Contextual PII — explicit gap
v4 does **not** add NER. The README's first paragraph (§8) says so. `docs/THREATS.md` lists the categories the gate cannot detect. Roadmap item for v5: spaCy `nb_core_news_sm` and `en_core_web_lg`.

### 4f. Document-format inputs
The gate input is plain text. Document explicitly: extraction from PDF/DOCX/PPTX/HTML happens *upstream* and its faithfulness is the integrator's responsibility. The `PostToolUse` hook in particular runs after tool output is already textified — if a tool returned structured content, the textification step is the trust boundary, not the gate.

### 4g. Attachment handling at the Claude Code hook layer
`UserPromptSubmit` hook reads only the text portion of the submission. If an attachment is present (image/PDF), the hook emits `attachment_seen_unscanned` audit event and either (a) refuses with a user-visible message ("Spektralia cannot scan attachments — paste content as text"), or (b) proceeds with explicit `--allow-attachments` user setting. Default is refuse.

## 5. Classifier as adversary — canary corpus (`canary.py`) — §5

- **Canary corpus** lives in `src/spektralia/canary/corpus/`. Contains:
  - Known-bad payloads with deterministic expected classifier categories (e.g., `"alice@example.com sent 4111-1111-1111-1111"` → expect `["PII", "financial"]`).
  - Known-safe payloads (lorem ipsum, code snippets) → expect empty.
  - **Random-nonced** payloads that should still trigger on regex even if classifier passes (defends against backdoors triggered by specific substrings — backdoor can't be triggered when the substring is fresh each run).

- **At `SessionStart` and every N hours**: run the corpus. For each item, gate must produce the expected `block`/`pass` decision AND categories within tolerance. Drift → auto-freeze with category `"canary_drift"`.

- **`spektralia self-test`** runs the corpus on demand and prints pass/fail.

- **Third-party digest pinning (optional, recommended).** `Settings.expected_model_digest` overrides Ollama's self-reported digest. Mismatch → fail-closed. Intended use: an org publishes its expected digests in a separate channel (sigstore, git-signed file) and integrators consume that.

- **Classifier output is enum-bounded.** `categories` is an `Enum`, validation rejects anything outside. Raw classifier JSON is never surfaced to humans, errors, or downstream prompts.

## 6. Operational proof (`heartbeat.py`, hook checks) — §6

- **Heartbeat events** emitted every `Settings.heartbeat_seconds` (default 300) and every `Settings.heartbeat_every_n_calls` (default 100), whichever first. Includes: pattern_hash, model_digest, prompt_hash, counter snapshot, sink type, last canary result. A downstream monitor watching for absence of heartbeats catches a stopped gate within a known window.

- **`spektralia hook-check`** (CLI) reads `~/.claude/settings.json` and asserts all expected hooks are present, point to the current gate, and the pattern_hash matches what the installed gate would produce. Exit 2 on missing/mismatched. Documented to run on `SessionStart`.

- **Override-rate counter** in `anomaly.py`. Every soft-mode override (§8) increments a rolling counter; sustained-high override rate emits `override_rate_high` audit event (does not auto-freeze; the human is in the loop).

## 7. Conversation-history leakage (cloud side) — §7

The gate cannot reach above the Claude Code → Anthropic API boundary; v4 makes the consequences explicit and ships what mitigations are available.

- **`spektralia scan-config`** lints `~/.claude/CLAUDE.md` and every project `CLAUDE.md` for sensitive content (uses the same gate). Reports findings without modifying. Recommended to run in CI for any repo using Claude Code.

- **`/compact` warning.** Documentation explicitly warns: Claude Code's `/compact` summarizes conversation history above the API, including model outputs, and the gate does not see the summary. Recommend: avoid `/compact` in sessions that processed sensitive content; start a fresh session instead.

- **Model output is not gated.** Stated as a deliberate non-goal. Recommended mitigation for high-risk users: a future "outbound gate" component that scans the full outbound `messages` array on a custom client (out of scope for v4; out of reach for Claude Code without a fork).

- **Prompt-caching tradeoff documented.** Random-suffix tokens defeat prompt caching (every request differs). Stable tokens enable caching but reintroduce a per-token correlation oracle visible to the cloud model. v4 picks **random suffixes / no caching** as default and documents the tradeoff; a future opt-in `Settings.prompt_cache_friendly_tokens=True` is mentioned as a roadmap item.

- **System-prompt drift.** `scan-config` covers static CLAUDE.md. The dynamic system prompt Claude Code assembles per session is not visible to the gate; documented gap.

## 8. UX failure modes — §8

- **README opening paragraph** (verbatim spec):
  > *Spektralia is a sensitivity gate, not a sensitivity guarantee. It detects what its rules and a small local classifier can see — credentials with known shapes, identifiers with valid checksums, high-entropy strings, and content the classifier flags. It does not detect contextual personal data (names in prose, employment history, dates of birth as words), novel credential formats, or content the classifier has never seen. Use Spektralia as one control in a defense-in-depth posture, not as the sole boundary between your data and a cloud LLM.*

- **Soft mode.** `Settings.mode in {"strict", "soft"}` (default `strict`). In `soft`, classifier-only flags (no regex hit, no rules hit) produce a user prompt: "Spektralia flagged the following categories — proceed? [y/N]". Rule hits always block; cannot be soft-overridden. Every override emits `user_override` audit event with categories.

- **`--explain` mode.** `spektralia scan --explain` and the hook equivalent show which detectors ran, what they found, what categories the classifier returned, and what the block reason was (in labels/categories only — never values). Surfaces the gap explicitly to the user so they understand *why* something passed or blocked.

- **Actionable block reasons.** Block message is structured: `Blocked: rule(EMAIL,IP_ADDR) + classifier(0.91, [PII])`. Specific enough to act on, generic enough not to leak values. Documented prohibition: never include the offending value in any user-visible message.

- **Mutation-until-pass detector.** If three submissions within a session each hit the same categories, the next attempt to soft-override is denied even in soft mode (category `"mutation_pattern_detected"`). Heuristic, documented.

## 9. Claude Code hook surface — §9

- **`PreToolUse(Task)` is now required** in the example settings.json. The `Task` tool spawns a subagent with a new prompt; that prompt argument is sensitive content originating in the parent agent's context and must be gated. Without this hook, a parent agent can launder accumulated context into a subagent and out.

- **`SessionStart` hook**:
  - Runs `verify-integrity`.
  - Runs `self-test` (canary corpus).
  - Runs `hook-check`.
  - Runs `verify-installed` (dependency drift).
  - Refuses to start the session if any fail.

- **`Stop` hook**: emits final audit `session_end` roll-up event; calls `audit-verify` on the just-finished session's slice and warns if the chain broke.

- **Default-deny MCP policy.** Hook configuration uses `matcher: ".*"` (regex match all tools) for `PreToolUse` and `PostToolUse`, with an explicit `exempt: [...]` list of tool names whose arguments/outputs are known-safe to skip. New MCP servers therefore enroll automatically. Documented carefully; the exempt list ships empty.

- **Hook crash semantics.** Each hook script wraps its body in `try/except`; on uncaught exception, exits with code that Claude Code treats as "block" (verified against Claude Code's documented hook contract). A test deliberately raises inside each hook and asserts the prompt/tool is blocked, not silently allowed.

- **Hook-output sanitization.** Hooks themselves must not print sensitive content in their stderr/stdout (Claude Code surfaces hook stderr to the user/logs). All hook diagnostics use labels only.

- **Settings.example.json** committed and referenced in install docs. Single source of truth for the canonical hook configuration; integrators copy and adjust paths only.

## 10. Performance / DoS — §10

- **`API_KEY_GENERIC` rewritten as ReDoS-safe.** New form anchors more strictly, removes nested optional `\s*`, and uses possessive quantifiers via the `regex` module (PyPI `regex`, not stdlib `re`). Stdlib `re` does not support timeouts; `regex` supports `timeout=` per call. Every pattern compilation goes through a wrapper that enforces a 100ms per-pattern timeout — exceeded patterns produce `Detection(label="REGEX_TIMEOUT", ...)` and the gate treats the input as "rule could not complete" (fail-closed).

- **ReDoS fuzz in CI.** A nightly job runs `recheck` (or equivalent) over every pattern; any ReDoS-positive result fails the build.

- **Single-framing "fast" mode.** `Settings.classifier_mode in {"strict", "fast"}` selects two-framing vs single-framing consensus. Hook integration uses:
  - `UserPromptSubmit` → strict (low frequency, high stakes).
  - `PreToolUse(Task)` → strict (subagent leak risk).
  - `PreToolUse(Bash/Write/Edit)` → strict.
  - `PostToolUse(*)` → fast (high frequency, large outputs, lower stakes per call).

- **Cache invalidation triggers.** Cache flushes on: config change (already in v3), model digest change, pattern hash change, prompt hash change, **freeze/unfreeze**, **canary drift**, **self-test failure**. Documented as the complete list.

- **Performance budget** documented per hook: UserPromptSubmit ≤ 500ms p95, PreToolUse ≤ 300ms p95, PostToolUse ≤ 200ms p95 on 10KB input. CI benchmark enforces.

## 11. Compliance framing (`docs/COMPLIANCE.md`) — §11

Spektralia makes no compliance certification claims. The doc states:

- **GDPR**:
  - Spektralia is a processor of personal data when run; lawful basis depends on deployer (legitimate interest for self-hosted personal use; controller/processor agreement for organizational use).
  - Data-minimization: audit log contains labels and categories only; never values. This is normative, not aspirational — enforced by `test_no_secret_in_exceptions.py` and a `test_audit_no_values.py` that fuzzes audit calls.
  - Retention: audit log requires explicit rotation policy. `spektralia audit-rotate --keep-days N` provided.
  - Right to erasure: `spektralia audit-purge --before <date>` provided; chain re-anchored from purge point with explicit `"chain_anchor_after_purge"` event.
  - Cross-border transfer: documents Spektralia's role as a technical measure under Art. 32 that data exporters may cite (not legal advice — framing only).

- **Datatilsynet (Norway)**: NO_PID detection + Norwegian-context defaults call out alignment with Datatilsynet's published AI guidance. Links included.

- **PCI-DSS**:
  - Never-log-values is treated as a PCI compliance constraint, not a stylistic choice.
  - PAN detection covers Luhn-valid candidates; coverage of all card schemes documented; magnetic-stripe data and CVV2 are NOT detected and that gap is explicit.
  - Caching of payloads containing PAN is bounded by the size cap and the cache content (sanitized text only, originals never in cache). Stated.

- **HIPAA**:
  - No PHI patterns ship in v4. Loud disclaimer for US healthcare deployments. Roadmap item: ICD-10 codes, NPI numbers (Luhn variant), MRN heuristics (configurable per institution).

- **Audit log itself contains personal data** (labels of personal data processing events). Falls under GDPR. Retention + access + RTE rules apply. Documented.

## 12. Smaller items folded in — §12

- **Versioned CLI surface.** `spektralia --api-version` prints the integer subcommand-stability version. Breaking subcommand changes bump it; scripts target a specific version.
- **`gate_sync` documented thread-unsafe** unless `Settings.thread_safe=True` (off by default, adds a re-entrant lock + per-thread counter).
- **Single `config_hash` definition.** Enumerated list in `config.py` with a `test_config_hash_covers_all_settings.py` that fails if a `Settings` field is added without registering it (or explicitly excluding it as non-policy-affecting).
- **`pattern-set version` retired** in favor of `pattern_hash`. References updated everywhere.
- **Random-suffix collision check.** Sanitizer asserts suffix uniqueness within a request map; re-rolls on collision (extremely rare but explicit).
- **`min()` consensus exposed as anomaly signal.** When two-framing `max - min > Settings.framing_disagreement_threshold`, emit `framing_disagreement` audit event in addition to the block/pass decision based on `max`.
- **`unsafe_restore` whitelist is schema-aware** — JSONPath expressions per integration, not global field names.
- **Pattern hot-reload disallowed.** Pattern hash captured at gate construction; reload requires process restart (which re-anchors the audit chain). Simpler invariant; documented.
- **Time recording**: both `time.time_ns()` (wall) and `time.monotonic_ns()` (monotonic) recorded per audit event.
- **IDN email** handled by encoding the regex against `idna`-decoded form *and* the original; both contribute detections.
- **`GateResult.detections` no longer carries values.** `Detection` has `label`, `span`, and a `value_ref` that resolves through the private `Sanitized` only when called with the unsafe-restore guard. Closes the "integrator logs `detections` raw" footgun.

## Verification (v4 additions on top of v2+v3)

1. v2 and v3 tests all pass.
2. **Ollama trust**:
   - UDS path with wrong owner/mode → gate refuses to start.
   - TCP pin: changing the listening process between calls → freeze.
   - Model digest mismatch → freeze.
3. **Filesystem**:
   - Symlinked `~/.spektralia/FREEZE` → treated as anomalous freeze.
   - Group-readable audit file → sink refuses.
   - Audit chain survives a forced kill; `audit-verify` succeeds across the restart boundary.
4. **Memory hygiene**:
   - Strace-style memory inspection test: after gate processes a payload and returns, a known-secret byte sequence is no longer findable in the `Secret`'s buffer.
   - Every exception path on every detector run with a known-secret input never includes the value.
5. **Detection**:
   - Zero-width-inside-credit-card → still detected.
   - Bidi-override input → stripped and audited.
   - Greek/Armenian-homoglyph `api_key` → detected.
   - Base64-encoded JSON containing an email → detected (`EMAIL_ENCODED`).
   - PEM body without headers → detected.
   - Line-wrapped credit card → detected.
6. **Classifier-as-adversary**:
   - Canary corpus runs at SessionStart; deliberately swapping the model to one that "always passes" trips `canary_drift` and freezes.
   - Backdoor-style payload (with random nonce) still blocks via regex even when classifier returns safe.
7. **Operational proof**:
   - Heartbeat events appear at expected intervals.
   - `hook-check` fails when a hook is removed from settings.json.
   - `scan-config` flags sensitive content in CLAUDE.md test fixtures.
8. **UX**:
   - Soft mode prompts on classifier-only flags; rule hits remain hard-block.
   - Mutation-until-pass: three same-category submissions then a soft-override → denied with `mutation_pattern_detected`.
9. **Hook surface**:
   - `PreToolUse(Task)` blocks a subagent prompt containing a known secret.
   - `SessionStart` refuses to start when canary fails.
   - Default-deny: a fictional new MCP tool not in `exempt` triggers the hook on first use.
   - Each hook with a deliberately raised exception → the action is blocked, not silently allowed.
10. **Perf/DoS**:
    - `API_KEY_GENERIC` against the ReDoS-fuzz input → bounded by 100ms timeout, classified as `REGEX_TIMEOUT`, fail-closed.
    - Benchmark suite enforces per-hook latency budgets.
11. **Compliance**:
    - `test_audit_no_values.py` fuzzes the audit interface and asserts no field ever contains a known secret.
    - `audit-purge` re-anchors the chain and emits the documented event.
12. **Smaller items**:
    - `config_hash` test fails when a new `Settings` field is unregistered.
    - `framing_disagreement` event emitted when the two framings disagree by > threshold.

## ASI coverage after v4

| Risk | v3 | v4 |
|------|----|----|
| ASI-01 Prompt Injection | PASS | **PASS+** (canary corpus + bounded enum output + default-deny MCP matchers) |
| ASI-02 Tool Use | N/A | N/A (library) |
| ASI-03 Excessive Agency | N/A | N/A (library) |
| ASI-04 Escalation | N/A | N/A (library) |
| ASI-05 Trust Boundary | PASS | **PASS+** (Ollama channel hardened; `unsafe_restore` schema-aware; `detections.value` removed from public surface) |
| ASI-06 Audit | PASS (per-process chain) | **PASS+** (persistent chain across restarts; sink abstraction with journald default) |
| ASI-07 Identity | N/A | N/A |
| ASI-08 Policy Bypass | PASS | **PASS+** (default-deny MCP; `Task` covered; bounded enum output; hook-check + scan-config + verify-installed at session start) |
| ASI-09 Supply Chain | PASS | **PASS+** (UDS/PID/exe Ollama pinning; third-party digest support; `verify-installed` enforced at session start) |
| ASI-10 Anomaly | PASS | **PASS+** (canary drift, override-rate, framing-disagreement, mutation-pattern, heartbeat presence) |

## Out of scope (v4)

- Outbound message gate at the Anthropic client level (would require a custom client or forked Claude Code).
- NER for contextual PII (v5 roadmap).
- HIPAA-specific patterns (v5 roadmap if a healthcare adopter shows up).
- Distributed audit chain across machines.
- Kernel-level local attacker defense.
- macOS/Windows feature parity for memory hygiene (`PR_SET_DUMPABLE` is Linux-only; documented as gap).
