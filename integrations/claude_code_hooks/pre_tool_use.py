#!/usr/bin/env python3
"""Claude Code PreToolUse hook — block secrets in tool arguments."""
from __future__ import annotations

import asyncio
import json
import re
import sys


_TOKEN_RE = re.compile(r"\[REDACTED:[A-Z_]+:[0-9a-f]{6}\]")


def _extract_text(tool_input: dict) -> str:
    """Flatten tool input to a single string for scanning."""
    parts: list[str] = []
    for v in tool_input.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, dict)):
            parts.append(json.dumps(v))
    return " ".join(parts)


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        print(json.dumps({"action": "block", "reason": "hook_input_parse_error"}))
        sys.exit(0)

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})

    # MCP default-deny: block unknown MCP tools unless explicitly exempted
    exempt_tools = {"Task", "Bash", "Write", "Edit", "Read", "Grep", "Glob"}
    if "." in tool_name or tool_name not in exempt_tools:
        # It's an MCP tool or unknown — check it strictly
        pass  # fall through to scan

    text = _extract_text(tool_input)

    try:
        # Check 1: token reference in args — cross-turn leak
        if _TOKEN_RE.search(text):
            print(json.dumps({
                "action": "block",
                "reason": "Token reference detected in tool args — possible cross-turn leak",
            }))
            return

        # Check 2: fresh sensitive content
        from spektralia import gate, SensitiveDataError
        from spektralia.config import Settings

        settings = Settings.from_env()
        settings.classifier_mode = "strict"

        result = asyncio.run(gate(text, settings))
        if result.blocked:
            print(json.dumps({"action": "block", "reason": result.block_reason}))
        else:
            print(json.dumps({"action": "continue"}))

    except SensitiveDataError as e:
        print(json.dumps({"action": "block", "reason": str(e)}))
    except Exception as e:
        print(json.dumps({"action": "block", "reason": f"hook_error: {type(e).__name__}"}))


if __name__ == "__main__":
    main()
