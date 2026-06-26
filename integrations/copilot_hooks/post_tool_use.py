#!/usr/bin/env python3
"""Copilot PostToolUse hook — block sensitive tool output."""

from __future__ import annotations

from _common import emit, load_claude_hook, read_payload


def handle(payload: dict) -> dict:
    try:
        result = load_claude_hook("post_tool_use").handle(payload)
    except Exception as e:
        return {"decision": "block", "reason": f"hook_error: {type(e).__name__}"}

    if result.get("decision") == "block":
        return {"decision": "block", "reason": result.get("reason", "Spektralia blocked output")}
    return {}


def main() -> None:
    payload = read_payload()
    if not payload:
        emit({"decision": "block", "reason": "hook_input_parse_error"})
        return
    emit(handle(payload))


if __name__ == "__main__":
    main()
