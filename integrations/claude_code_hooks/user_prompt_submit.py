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
            "decision": "block",
            "reason": "Spektralia cannot scan attachments — paste content as text",
        }

    try:
        from spektralia import SensitiveDataError, gate
        from spektralia.config import Settings
    except Exception as e:
        return {"decision": "block", "reason": f"hook_import_error: {type(e).__name__}"}

    try:
        settings = Settings.from_env()
        settings.classifier_mode = "strict"

        result = asyncio.run(gate(prompt, settings))

        if result.blocked:
            return {"decision": "block", "reason": result.block_reason}
        return {}

    except SensitiveDataError as e:
        return {"decision": "block", "reason": str(e)}
    except Exception as e:
        return {"decision": "block", "reason": f"hook_error: {type(e).__name__}"}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        print(json.dumps({"decision": "block", "reason": "hook_input_parse_error"}))
        sys.exit(0)

    result = handle(payload)
    if result:
        print(json.dumps(result))


if __name__ == "__main__":
    main()
