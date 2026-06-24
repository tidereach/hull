#!/usr/bin/env python3
"""Claude Code UserPromptSubmit hook — scan and sanitize user prompt."""
from __future__ import annotations

import asyncio
import json
import sys


def handle(payload: dict) -> dict:
    prompt = payload.get("prompt", "")

    if payload.get("attachments"):
        return {
            "action": "block",
            "reason": "Spektralia cannot scan attachments — paste content as text",
        }

    try:
        from spektralia import gate, SensitiveDataError
        from spektralia.config import Settings

        settings = Settings.from_env()
        settings.classifier_mode = "strict"

        result = asyncio.run(gate(prompt, settings))

        if result.blocked:
            return {"action": "block", "reason": result.block_reason}
        return {"action": "continue", "prompt": result.sanitized_text}

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
