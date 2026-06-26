# Claude Code Hooks — Agent Instructions

This directory contains the five Python scripts that plug Spektralia into Claude Code's hook system. Read this before touching any file here.

## What lives here

| File | Hook event | Role |
|------|-----------|------|
| `session_start.py` | `SessionStart` | Integrity checks at session open; blocks session on failure |
| `user_prompt_submit.py` | `UserPromptSubmit` | Scans + sanitizes the typed prompt (strict mode) |
| `pre_tool_use.py` | `PreToolUse` | MCP default-deny; scans `Task`/`Bash`/`Write`/`Edit` args (strict) |
| `post_tool_use.py` | `PostToolUse` | Scans tool output before it enters context (fast mode) |
| `stop.py` | `Stop` | Emits `session_end` audit roll-up |
| `settings.example.json` | — | Template; copy to `.claude/settings.json` or run `spektralia install-hooks` |

## Critical invariants — do NOT break these

- **Fail-closed everywhere.** Every hook wraps its body in `try/except`. A crash or unexpected exception must exit with `{"action": "block", "reason": "..."}`, never silently. This is a hard security requirement (SPEC §18).
- **`PreToolUse` must scan `Task` AND `Agent`.** SPEC §18 names the subagent-spawn tool `"Task"`, but some Claude Code versions use `"Agent"`. Both names must remain in `_STRICT_SCAN_TOOLS` or subagent prompt laundering bypasses `UserPromptSubmit`.
- **Own-source exclusion must stay.** `pre_tool_use.py` and `post_tool_use.py` skip files under `_OWN_SOURCE_SEGMENTS` (`/src/spektralia/`, `/integrations/claude_code_hooks/`). Removing this exclusion causes self-scan false positives.
- **MCP default-deny is unconditional.** The `mcp__` prefix check in `pre_tool_use.py` has no allowlist. Do not add one without explicit authorization and an audit event.
- **JSON output shape.** Each hook must return a valid Claude Code hook response. The accepted shapes are: `{"action": "block", "reason": "..."}` to block, or `{"action": "continue"}` / `{}` / `{"output": "..."}` to pass. Wrong shapes fail silently or cause crashes — add a contract test for any new hook.

## Testing hooks

The test suite for hooks is in `tests/test_hooks.py`. Run it with:

```bash
.venv/bin/pytest tests/test_hooks.py -v
```

Each hook script exports a `handle(payload: dict) -> dict` function. Tests call `handle()` directly — do not test hooks by exec-ing the script, call `handle()` instead.

When adding a new hook or changing behavior, verify:
1. `handle()` never raises an exception (catches everything and returns `{"action": "block", ...}`)
2. The JSON output shape matches the contract above
3. The new behavior has a test in `test_hooks.py`

## Installing hooks

**Automated (recommended):**

```bash
spektralia install-hooks          # write to .claude/settings.json (project-scoped)
spektralia install-hooks --dry-run # preview without writing
```

**Manual:**
Copy `settings.example.json` to `.claude/settings.json` (project) or `~/.claude/settings.json` (global). Replace `/path/to/spektralia` with the absolute path of this repo. Then verify:

```bash
spektralia hook-check
```

## Classifier modes

- `UserPromptSubmit` and `PreToolUse` use **strict mode** (two-framing Ollama consensus, ~400ms).
- `PostToolUse` uses **fast mode** (single framing, ~200ms) to bound per-tool-call latency.
- `SessionStart` and `Stop` do not call the classifier at all.

Do not change a hook from strict → fast without understanding the latency / accuracy tradeoff and documenting it.

## Token map lifecycle

Each hook invocation creates its own in-memory token map. Maps are never persisted between calls, never reused across turns. A `[REDACTED:*:*]` token reference in a tool argument crossing turns is treated as a cross-turn leak and blocked by `PreToolUse`.

## What hooks do NOT cover

- The Anthropic API response stream (Claude's replies are not scanned here).
- `/compact` conversation summaries (above the API boundary).
- Dynamic system prompts assembled per session by Claude Code.

See `docs/SPEC.md §18` for the full integration design and threat model.
