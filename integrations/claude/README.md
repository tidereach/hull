# Spektralia — Claude Code Hook Integration

Five hooks gate every I/O surface in a Claude Code session: the user prompt, tool arguments before execution, tool output before it enters context, session integrity at startup, and a session-end audit roll-up.

## Quick install

```bash
spektralia install-hooks          # auto-detect project/global scope
spektralia install-hooks --dry-run # preview
```

Or manually: copy `settings.example.json` to `.claude/settings.json` (project) or `~/.claude/settings.json` (global), replace `/path/to/spektralia`, then run `spektralia hook-check`.

## What each hook does

| Hook | File | Classifier mode | Effect |
|------|------|-----------------|--------|
| `SessionStart` | `session_start.py` | — | Integrity + self-test + hook-check at session open; blocks on failure |
| `UserPromptSubmit` | `user_prompt_submit.py` | strict | Scans + sanitizes the typed prompt; blocks on rule hit or classifier high |
| `PreToolUse` | `pre_tool_use.py` | strict | MCP default-deny; scans `Task`/`Agent`/`Bash`/`Write`/`Edit` args |
| `PostToolUse` | `post_tool_use.py` | fast | Scans tool output before it enters Claude's context |
| `Stop` | `stop.py` | — | Emits `session_end` audit roll-up |

See [`AGENTS.md`](AGENTS.md) for agent-facing instructions including invariants, testing patterns, and gotchas. See [`docs/SPEC.md §18`](../../docs/SPEC.md) for the full integration design.
