#!/usr/bin/env python3
"""Claude Code UserPromptSubmit hook — scan and sanitize user prompt."""
from __future__ import annotations

import asyncio
import json
import sys


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        # Cannot read input — block
        print(json.dumps({"action": "block", "reason": "hook_input_parse_error"}))
        sys.exit(0)

    prompt = payload.get("prompt", "")

    # Check for attachments
    if payload.get("attachments"):
        print(json.dumps({
            "action": "block",
            "reason": "Spektralia cannot scan attachments — paste content as text",
        }))
        sys.exit(0)

    try:
        from spektralia import gate, SensitiveDataError
        from spektralia.config import Settings

        settings = Settings.from_env()
        settings.classifier_mode = "strict"

        result = asyncio.run(gate(prompt, settings))

        if result.blocked:
            # Soft-mode warn — output the block reason for user decision
            print(json.dumps({
                "action": "block",
                "reason": result.block_reason,
            }))
        else:
            # Substitute sanitized text
            print(json.dumps({
                "action": "continue",
                "prompt": result.sanitized_text,
            }))

    except SensitiveDataError as e:
        print(json.dumps({"action": "block", "reason": str(e)}))
    except Exception as e:
        # Fail-closed: any unexpected error blocks
        print(json.dumps({"action": "block", "reason": f"hook_error: {type(e).__name__}"}))
        sys.exit(0)


if __name__ == "__main__":
    main()
