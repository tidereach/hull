#!/usr/bin/env python3
"""Claude Code PostToolUse hook — rule-only scan of tool output before it enters context."""
from __future__ import annotations

import json
import sys


def handle(payload: dict) -> dict:
    output = payload.get("output", "")
    if not isinstance(output, str):
        output = json.dumps(output)

    try:
        from spektralia.scanner import scan

        detections = scan(output)
        if detections:
            labels = "+".join(sorted({d.label for d in detections}))
            return {"decision": "block", "reason": f"rule({labels})"}
        return {}

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
