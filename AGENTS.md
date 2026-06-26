# Spektralia

Local pre-cloud sensitivity gate. Normalizes and scans input for PII, credentials, and internal identifiers before any cloud LLM call; classifies residual risk locally via Ollama; blocks or passes the sanitized payload.

**Authoritative design spec:** [`docs/SPEC.md`](docs/SPEC.md) — read this before touching any code. [`docs/PLAN.md`](docs/PLAN.md) has phased status and open bugs. [`docs/RATIONALE.md`](docs/RATIONALE.md) has the full design arguments. [`docs/ENDPOINT_STACK.md`](docs/ENDPOINT_STACK.md) shows how Spektralia composes with a sandbox (Fence) and a Falco policy layer (Prempti) into a layered endpoint stack; [`docs/SANDBOX_ALTERNATIVES.md`](docs/SANDBOX_ALTERNATIVES.md) compares Fence with [navikt/cplt](https://github.com/navikt/cplt) as the execution-plane sandbox. [`docs/TEST.md`](docs/TEST.md) is a step-by-step verification guide with expected test counts.

---

## Architecture

```
input
  │
  ▼  normalize (NFKC + strip zero-width/bidi/homoglyphs)
  ▼  scan      (regex + Luhn/MOD-11 validators + entropy + decoded payloads)
  ▼  sanitize  (random-suffix typed tokens; no public restore())
  ▼  classify  (Ollama, format=json, two-framing consensus, fail-closed)
  ▼  gate      (rule_hit OR classifier_high → block; else pass)
  │
  ▼ sanitized payload → cloud LLM call
```

Every action produces a hash-chained audit event. A canary corpus runs at startup and on a schedule; drift auto-freezes the gate.

---

## File layout

```
src/spektralia/
  __init__.py          gate, gate_sync, SensitiveDataError, GateResult, Settings
  config.py            Settings; precedence: kwargs > env > toml > defaults
  patterns.py          Pattern(label, regex, validator, priority)
  normalize.py         NFKC, strip obfuscation chars, homoglyph fold
  scanner.py           Detection dataclass, scan(), span dedupe
  entropy.py           Shannon entropy, token-boundary, allowlist
  decode.py            base64/hex/gzip unwrap + re-scan
  memory_safety.py     Secret(bytearray), zeroize, PR_SET_DUMPABLE
  sanitizer.py         random-suffix tokens, private _restore
  classifier.py        Ollama format=json, two framings, fast mode
  ollama_trust.py      UDS preferred; TCP with PID/exe pin fallback
  sandbox.py           execution-plane sandbox preflight (fence/cplt); called by check-sandbox
  cache.py             LRU keyed on sha256(sanitized_text + config_hash + pattern_hash + model_digest + prompt_hash)
  canary.py            corpus self-test, drift → auto-freeze
  integrity.py         pattern hash, model digest, dep lockfile check
  anomaly.py           rolling counters, auto-freeze, freeze file
  heartbeat.py         periodic audit emission
  audit.py             hash-chained, persistent, sink abstraction
  gate.py              orchestration, soft mode, --explain
  errors.py            SensitiveDataError
  cli.py               versioned subcommands

scripts/
  latency_bench.py     per-hook p95 latency benchmark (mocks Ollama with respx)
  redos_fuzz.py        adversarial ReDoS input fuzz; used by nightly redos-fuzz.yml CI

docs/
  COMPLIANCE.md        GDPR/Datatilsynet/PCI-DSS/HIPAA/OWASP ASI Top 10 coverage
  THREATS.md           threat model — in-scope, out-of-scope, what gate does NOT detect

integrations/claude_code_hooks/
  session_start.py     verify-integrity + self-test + hook-check
  user_prompt_submit.py
  pre_tool_use.py      Task, Bash, Write, Edit + default-deny MCP
  post_tool_use.py     Read, Bash, Grep, Glob, MCP results
  stop.py
  settings.example.json
```

---

## Commands

```bash
# Install (dev)
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pre-commit install   # wire git hooks (ruff, black, mypy, end-of-file-fixer, check-yaml)

# Run tests
.venv/bin/pytest -q

# CLI
spektralia scan                   # stdin → sanitized stdout; exit 2 on block
spektralia scan --explain         # show which detectors ran and why
spektralia self-test              # run canary corpus against live classifier
spektralia verify-integrity       # print pattern/model/prompt hashes
spektralia verify-installed       # check pip hashes against requirements.lock
spektralia stats                  # rolling counters + freeze state
spektralia freeze / unfreeze
spektralia audit-verify <path>
spektralia audit-rotate --keep-days <N>   # prune old audit records; re-anchors chain
spektralia audit-purge --before YYYY-MM-DD # GDPR Right to Erasure; re-anchors chain
spektralia scan-config            # lint AGENTS.md / CLAUDE.md files for sensitive content
spektralia hook-check             # assert Claude Code hooks installed correctly
spektralia check-ollama           # ping configured Ollama endpoint
spektralia check-sandbox          # assert configured execution-plane sandbox (fence|cplt) is present

# SBOM / supply chain
make sbom    # regenerate SBOM.json from requirements.lock (reproducible; lockfile-based)
make verify  # verify-integrity + verify-installed
make test    # .venv/bin/pytest -q
make lock    # re-pin requirements.lock with hashes (uv pip compile --python-version 3.11 --generate-hashes)
```

---

## Key decisions (see spec §§ for full rationale)

- **Fail-closed default.** Classifier outage → block, not pass. Toggle via `SPEKTRALIA_FAIL_OPEN=1`.
- **No public `restore()`.** Tokens are one-way by default; restoration is a private, opt-in, whitelist-required, single-use API.
- **`rule_hit OR classifier_high` to block.** Neither layer can unilaterally pass; either can block.
- **Two-framing classifier consensus.** `max(framing1, framing2)` confidence; disagreement is its own audit event.
- **Ollama trust.** Prefer UDS with 0600 owner-check; TCP fallback pins PID + binary hash.
- **Canary corpus.** If the classifier starts returning wrong answers (backdoored model, drift), the gate auto-freezes.
- **Audit chain persists across restarts.** `~/.spektralia/audit.state` holds the last hash; new sessions anchor to it.
- **`PreToolUse(Task)` hook is required.** Without it, a parent agent can launder context into a subagent prompt and bypass `UserPromptSubmit`.

---

## Dependencies

```
httpx>=0.27
regex          # ReDoS-safe patterns with per-call timeout
keyring        # optional: TOML HMAC verification
```

Dev: `pytest pytest-asyncio respx cyclonedx-bom pip-tools pytest-cov mypy black ruff pip-audit`

Toolchain (install separately — not pip packages): `uv` (for `make lock`), `pre-commit` (for git hooks)

Ollama: `ollama pull llama3.1:8b`

---

## Claude Code hook integration

Copy `integrations/claude_code_hooks/settings.example.json` into `.claude/settings.json`
(project) or `~/.claude/settings.json` (global); replace `/path/to/spektralia` with the repo root.

| Hook | Effect |
|------|--------|
| `UserPromptSubmit` | Scans + sanitizes user prompt; blocks or substitutes |
| `PreToolUse` | Blocks sensitive data in Task/Bash/Write/Edit args; default-deny MCP |
| `PostToolUse` | Scans tool output before it re-enters context |
| `SessionStart` | Runs `verify-integrity` + canary self-test + `hook-check` |
| `Stop` | Emits session-end audit event |

**`PreToolUse(Task)` is required** — without it a parent agent can launder context into a subagent prompt and bypass `UserPromptSubmit`.

```bash
spektralia hook-check   # verify all hooks are wired correctly
```


---

## Gotchas

- **Entropy allowlist is matched against the original *and* punctuation-stripped token.**
  `find_high_entropy` strips `/ \ : -` (and similar) before the entropy calc, but the file-path
  and UUID allowlist matchers anchor on those exact characters. The scan loop checks
  `_is_allowlisted(token) or _is_allowlisted(clean)` for this reason — checking only the stripped
  form silently disables file-path exemption for absolute paths (the `/` prefix is gone), which is
  the false positive fixed in #22. Any new allowlist matcher must tolerate being run on both forms.
  See SPEC §6 for the full table.

- **`gate()` raises, does not return, on hard block.** In strict mode (default), `gate()` raises
  `SensitiveDataError`. It only returns `GateResult(blocked=True)` in soft mode
  (`SPEKTRALIA_MODE=soft`). All callers must `try/except SensitiveDataError`.

- **TOML config requires `[spektralia]` section.** Top-level keys in `.spektralia.toml` or
  `~/.spektralia/config.toml` are silently ignored. All settings must be under `[spektralia]`.

- **macOS: 1 test skipped.** `test_pr_set_dumpable` tests a Linux-only syscall (`PR_SET_DUMPABLE`)
  and skips on macOS. Expected suite result on macOS: `1 skipped, 1 xfailed`.

- **`llama3.2:3b` produces classifier false positives.** Use `llama3.1:8b` (the default).
  `llama3.2:3b` returns `sensitive=True, confidence=1.0, categories=[]` for short benign text
  even with JSON schema constraints.

- **`spektralia hook-check` checks both global and project settings.**
  `~/.claude/settings.json` and `.claude/settings.json` (project root) are both scanned;
  hooks may live in either or both files.

- **SBOM is generated from `requirements.lock`, not the active environment.** `make sbom` runs
  `cyclonedx-py requirements --output-reproducible -o SBOM.json requirements.lock`. Never run
  `cyclonedx-py environment` for committed SBOMs — it captures dev extras and transitive deps that
  differ between machines.

- **`uv` is not a pip package — install it separately before running `make lock`.** `pip install uv`
  works, or use the official installer. `pip-compile` (pip-tools) does not support `--python-version`
  in v7.x, so the lock target uses `uv pip compile --python-version 3.11` to include conditional
  deps (e.g. `typing-extensions`) that only apply to Python < 3.13.

- **`recheck` is not on PyPI.** `pip install recheck` fails — no such package. The nightly `redos-fuzz.yml` CI
  workflow uses pure-Python timeout assertion instead: runs each pattern against adversarial input and asserts the
  `regex` module's 100 ms timeout guard fires (returns `REGEX_TIMEOUT`); hangs >500 ms mean the guard is broken.

---

## What this gate does NOT cover

- Contextual PII in prose (names, addresses — NER is a v2 roadmap item)
- Model outputs / assistant turns (gating prose response stream is the wrong surface)
- `/compact` summarization (happens above the API; start fresh sessions for sensitive work)
- Attachments in Claude Code prompts (refused by default; `--allow-attachments` to opt in)
