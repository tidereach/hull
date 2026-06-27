#!/usr/bin/env python3
"""Claude Code PreToolUse hook — block secrets in tool arguments."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

_TOKEN_RE = re.compile(r"\[REDACTED:[A-Z_]+:[0-9a-f]{6}\]")

# Tools whose arguments are scanned strictly. The subagent-spawn tool is required
# to prevent subagent prompt laundering past UserPromptSubmit (SPEC §18). SPEC names
# it "Task", but some Claude Code versions name it "Agent" — scan both to fail closed
# across versions (scanning a non-existent tool name is a harmless no-op).
_STRICT_SCAN_TOOLS = frozenset({"Task", "Agent", "Bash", "Write", "Edit"})


_OWN_SOURCE_SEGMENTS = (
    "/src/spektralia/",
    "/integrations/claude/hooks/",
)

# Detect the Spektralia project root from this hook file's location so the full
# repo tree (including /tests/) is exempt from own-source scanning. The resolved
# parent chain from __file__: hooks/ → claude/ → integrations/ → root (4 hops).
_PROJECT_ROOT: Path | None = None
try:
    _PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
except Exception:
    pass

# Claude Code's own internal directories — agent-generated state, not user-supplied
# content. The Ollama classifier is skipped for these paths (issue #99). The
# token-reference check still runs so cross-turn leaks are caught regardless of
# destination. Unlike _OWN_SOURCE_SEGMENTS (which skips all checks, because the
# patterns file itself would trip its own patterns), these only skip the gate call.
_CLAUDE_INTERNAL_SEGMENTS = (
    "/.claude/plans/",
    "/.claude/memory/",
    "/.claude/commands/",
    "/.claude/skills/",
)


def _is_own_source(file_path: str) -> bool:
    """Return True if file_path is under Spektralia's own source tree.

    Two checks in order:
    1. Path-segment substring match (works without knowing the install path).
    2. Project-root check derived from __file__ — covers /tests/ and any other
       repo directory not listed in _OWN_SOURCE_SEGMENTS.
    """
    normalised = file_path.replace("\\", "/")
    if any(seg in normalised for seg in _OWN_SOURCE_SEGMENTS):
        return True
    if _PROJECT_ROOT is not None:
        try:
            return Path(file_path).resolve().is_relative_to(_PROJECT_ROOT)
        except Exception:
            pass
    return False


def _is_claude_internal(file_path: str) -> bool:
    """Return True if file_path is under Claude Code's own internal directories."""
    normalised = file_path.replace("\\", "/")
    return any(seg in normalised for seg in _CLAUDE_INTERNAL_SEGMENTS)


def _extract_text(tool_input: dict) -> str:
    parts: list[str] = []
    for v in tool_input.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list | dict):
            parts.append(json.dumps(v))
    return " ".join(parts)


def _deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def handle(payload: dict) -> dict:
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})

    # Default-deny: block MCP tools outright — new servers enroll automatically.
    # Claude Code names MCP tools as mcp__<server>__<tool>.
    if tool_name.startswith("mcp__"):
        return _deny(f"MCP tool '{tool_name}' blocked by default-deny policy")

    # Only scan argument-carrying tools
    if tool_name not in _STRICT_SCAN_TOOLS:
        return {}

    # Skip scanning Spektralia's own source files — editing patterns.py or hook
    # scripts would trip the very patterns they define (false positive on self).
    if tool_name in {"Write", "Edit"}:
        file_path = tool_input.get("file_path", "")
        if file_path and _is_own_source(file_path):
            return {}

    text = _extract_text(tool_input)

    # Check 1: REDACTED token reference in args → cross-turn leak
    if _TOKEN_RE.search(text):
        return _deny("Token reference detected in tool args — possible cross-turn leak")

    # Skip the Ollama classifier for Claude Code's own internal directories.
    # These hold agent-generated state and trigger classifier false positives on
    # benign structured content (issue #99). Token-reference check above still runs.
    if tool_name in {"Write", "Edit"}:
        file_path = tool_input.get("file_path", "")
        if file_path and _is_claude_internal(file_path):
            return {}

    # Check 2: fresh sensitive content
    try:
        from spektralia import SensitiveDataError, gate
        from spektralia.config import Settings
    except Exception as e:
        return _deny(f"hook_import_error: {type(e).__name__}")

    try:
        settings = Settings.from_env()
        settings.classifier_mode = "strict"

        result = asyncio.run(gate(text, settings))
        if result.blocked:
            return _deny(result.block_reason)
        return {}

    except SensitiveDataError as e:
        return _deny(str(e))
    except Exception as e:
        return _deny(f"hook_error: {type(e).__name__}")


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        print(json.dumps(_deny("hook_input_parse_error")))
        sys.exit(0)

    result = handle(payload)
    if result:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
