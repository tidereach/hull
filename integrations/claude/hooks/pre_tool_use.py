#!/usr/bin/env python3
"""Claude Code PreToolUse hook — block secrets in tool arguments."""

from __future__ import annotations

import asyncio
import json
import re
import sys

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


def _is_own_source(file_path: str) -> bool:
    """Return True if file_path is under Spektralia's own source tree.

    Checked via path-substring match so the hook works regardless of cwd or
    whether the repo is checked out at an absolute path we don't know at
    install time. False positives (a user repo that happens to contain
    /src/spektralia/) are acceptable — scanning that directory would still be
    a no-op because the patterns file itself doesn't contain secrets.
    """
    normalised = file_path.replace("\\", "/")
    return any(seg in normalised for seg in _OWN_SOURCE_SEGMENTS)


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
