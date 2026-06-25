#!/usr/bin/env python3
"""Claude Code PreToolUse hook — block secrets in tool arguments."""

from __future__ import annotations

import asyncio
import json
import re
import sys

_TOKEN_RE = re.compile(r"\[REDACTED:[A-Z_]+:[0-9a-f]{6}\]")

# Tools whose arguments are scanned strictly. Agent is required to prevent
# subagent prompt laundering past UserPromptSubmit.
_STRICT_SCAN_TOOLS = frozenset({"Agent", "Bash", "Write", "Edit"})


def _extract_text(tool_input: dict) -> str:
    parts: list[str] = []
    for v in tool_input.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, dict)):
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
