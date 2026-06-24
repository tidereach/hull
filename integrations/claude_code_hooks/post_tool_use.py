#!/usr/bin/env python3
"""Claude Code PostToolUse hook — scan tool output before it enters context."""
from __future__ import annotations

import asyncio
import json
import sys


def handle(payload: dict) -> dict:
    output = payload.get("output", "")
    if not isinstance(output, str):
        output = json.dumps(output)

    try:
        from spektralia import gate, SensitiveDataError
        from spektralia.config import Settings

        settings = Settings.from_env()
        settings.classifier_mode = "fast"  # high-frequency hook

        result = asyncio.run(gate(output, settings))

        if result.blocked:
            return {"action": "block", "reason": result.block_reason}
        return {"action": "continue", "output": result.sanitized_text}

    except SensitiveDataError as e:
        return {"action": "block", "reason": str(e)}
    except Exception as e:
        return {"action": "block", "reason": f"hook_error: {type(e).__name__}"}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        print(json.dumps({"action": "block", "reason": "hook_input_parse_error"}))
        sys.exit(0)

    print(json.dumps(handle(payload)))


if __name__ == "__main__":
    main()
