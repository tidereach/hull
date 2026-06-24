# Spektralia

Local pre-cloud sensitivity gate. Normalizes and scans input for PII, credentials, and internal identifiers before any cloud LLM call; classifies residual risk locally via Ollama; blocks or passes the sanitized payload.

**Authoritative design spec:** [`SPEC.md`](SPEC.md) — read this before touching any code. [`PLAN.md`](PLAN.md) has phased status and open bugs. [`RATIONALE.md`](RATIONALE.md) has the full design arguments.

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

## File layout (target)

```
src/spektralia/
  __init__.py          gate, gate_sync, SensitiveDataError, GateResult
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
  cache.py             LRU keyed on sha256(text + config_hash)
  canary.py            corpus self-test, drift → auto-freeze
  integrity.py         pattern hash, model digest, dep lockfile check
  anomaly.py           rolling counters, auto-freeze, freeze file
  heartbeat.py         periodic audit emission
  audit.py             hash-chained, persistent, sink abstraction
  gate.py              orchestration, soft mode, --explain
  errors.py            SensitiveDataError
  cli.py               versioned subcommands

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
spektralia scan-config            # lint CLAUDE.md files for sensitive content
spektralia hook-check             # assert Claude Code hooks installed correctly
spektralia check-ollama           # ping configured Ollama endpoint

# SBOM
.venv/bin/cyclonedx-py environment -o SBOM.json  # regenerates SBOM.json
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

Dev: `pytest pytest-asyncio respx cyclonedx-bom`

Ollama: `ollama pull llama3.1:8b`

---

## Claude Code hook integration

Spektralia gates prompts via Claude Code hooks. Copy `integrations/claude_code_hooks/settings.example.json` into your project's `.claude/settings.json` (or merge into `~/.claude/settings.json` for global use), replacing `/path/to/spektralia` with the repo root.

```json
"hooks": {
  "UserPromptSubmit": [{"hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/user_prompt_submit.py"}]}],
  "PreToolUse":       [{"matcher": ".*", "hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/pre_tool_use.py"}]}],
  "PostToolUse":      [{"matcher": ".*", "hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/post_tool_use.py"}]}],
  "SessionStart":     [{"hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/session_start.py"}]}],
  "Stop":             [{"hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/stop.py"}]}]
}
```

**What each hook does:**

| Hook | File | Effect |
|------|------|--------|
| `UserPromptSubmit` | `user_prompt_submit.py` | Scans + sanitizes the user prompt before it reaches Claude; blocks or substitutes sanitized text |
| `PreToolUse` | `pre_tool_use.py` | Blocks Task/Bash/Write/Edit calls whose args contain sensitive data; default-deny on unrecognised MCP tools |
| `PostToolUse` | `post_tool_use.py` | Scans Read/Bash/Grep/Glob/MCP results before they re-enter context |
| `SessionStart` | `session_start.py` | Runs `verify-integrity` + canary self-test + `hook-check` at session open |
| `Stop` | `stop.py` | Emits a session-end audit event |

The `PreToolUse(Task)` hook is **required** — without it a parent agent can launder sensitive context into a subagent prompt and bypass `UserPromptSubmit`.

Verify hooks are wired correctly with:

```bash
spektralia hook-check
```

---

## What this gate does NOT cover

- Contextual PII in prose (names, addresses — NER is a v2 roadmap item)
- Model outputs / assistant turns (gating prose response stream is the wrong surface)
- `/compact` summarization (happens above the API; start fresh sessions for sensitive work)
- Attachments in Claude Code prompts (refused by default; `--allow-attachments` to opt in)
