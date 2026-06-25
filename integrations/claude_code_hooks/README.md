# Spektralia — Claude Code Hook Integration

Five hooks gate every I/O surface in a Claude Code session: the user prompt, tool arguments before execution, tool output before it enters context, session integrity at startup, and a session-end audit roll-up.

## Installation

1. Copy `settings.example.json` to `~/.claude/settings.json` (global) or `.claude/settings.json` (project-scoped).
2. Replace `/path/to/spektralia` with the absolute path to this repository root.
3. Verify: `spektralia hook-check`

```json
"hooks": {
  "SessionStart":      [{"hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/session_start.py"}]}],
  "UserPromptSubmit":  [{"hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/user_prompt_submit.py"}]}],
  "PreToolUse":        [{"matcher": ".*", "hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/pre_tool_use.py"}]}],
  "PostToolUse":       [{"matcher": ".*", "hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/post_tool_use.py"}]}],
  "Stop":              [{"hooks": [{"type": "command",
    "command": "python /path/to/spektralia/integrations/claude_code_hooks/stop.py"}]}]
}
```

## What each hook does

| Hook | File | Classifier mode | Effect |
|------|------|-----------------|--------|
| `SessionStart` | `session_start.py` | — | Runs `verify-integrity`, `self-test`, `hook-check`, `verify-installed`, `check-sandbox`, `check-prempti`; blocks session if any fail |
| `UserPromptSubmit` | `user_prompt_submit.py` | strict | Scans + sanitizes the typed prompt; substitutes sanitized text; blocks on rule hit or classifier high |
| `PreToolUse` | `pre_tool_use.py` | strict | MCP tools → default-deny block; `Task`/`Bash`/`Write`/`Edit` → scan args for token refs and fresh secrets |
| `PostToolUse` | `post_tool_use.py` | fast | Scans tool output before it enters Claude's context; substitutes sanitized version |
| `Stop` | `stop.py` | — | Emits `session_end` audit event |

## Security notes

**`PreToolUse(Task)` is mandatory.** Without it, a parent agent can pass sensitive context into a subagent prompt and bypass `UserPromptSubmit`.

**MCP default-deny.** Any tool whose name starts with `mcp__` is blocked. There is no allowlist. To permit an MCP tool, you must remove or adjust this hook — this is intentional friction. If you accept that risk, document your reasoning in an audit event.

**Attachments are blocked by default.** `UserPromptSubmit` refuses image/file/PDF blocks with "paste content as text." The gate cannot scan binary blobs.

**Hook crash semantics.** Every hook wraps its body in `try/except`; any uncaught exception exits with a "block" action. A crashing gate fails closed, never open.

**Classifier mode per hook.** `UserPromptSubmit` and `PreToolUse` use strict mode (two-framing consensus, slower). `PostToolUse` uses fast mode (single framing) to keep per-call latency under 200ms on 10KB outputs.

**Execution-plane sandbox check.** `SessionStart` runs `check-sandbox`. It is a no-op until you opt in by setting `sandbox_backend` (`fence` or `cplt`) in `.spektralia.toml` / `~/.spektralia/config.toml` or `SPEKTRALIA_SANDBOX_BACKEND`. Once set, a missing wrapper on `PATH` (or a drifted `SPEKTRALIA_SANDBOX_CONFIG_HASH` pin) blocks the session — fail-closed. See [`docs/SANDBOX_ALTERNATIVES.md`](../../docs/SANDBOX_ALTERNATIVES.md).

**Control-plane service check.** `SessionStart` also runs `check-prempti`, the control-plane analog. No-op until you set `prempti_backend = "prempti"` (or `SPEKTRALIA_PREMPTI_BACKEND`). Once set, a missing `premptictl` on `PATH`, an absent `prempti_socket`, or a drifted config-hash pin blocks the session — fail-closed. The full three-plane bring-up is in [`endpoint/`](../../endpoint/README.md).

## Token map lifecycle

Each hook call owns its own token map. Maps are never persisted, never reused across turns. Cross-turn token references in tool arguments (`[REDACTED:*:*]`) are treated as a cross-turn leak and blocked by `PreToolUse`.

## What the hooks do NOT cover

- The Anthropic API response stream (Claude's replies are not scanned).
- `/compact` conversation summaries (happen above the API; start fresh sessions for sensitive work).
- Dynamic system prompts assembled by Claude Code per session.

See `docs/SPEC.md §18` for the full integration design.
