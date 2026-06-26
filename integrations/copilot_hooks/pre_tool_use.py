#!/usr/bin/env python3
"""Copilot PreToolUse hook — block sensitive tool arguments."""

from __future__ import annotations

from _common import emit, load_claude_hook, read_payload


def _deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def handle(payload: dict) -> dict:
    try:
        return load_claude_hook("pre_tool_use").handle(payload)
    except Exception as e:
        return _deny(f"hook_error: {type(e).__name__}")


def main() -> None:
    payload = read_payload()
    if not payload:
        emit(_deny("hook_input_parse_error"))
        return
    emit(handle(payload))


if __name__ == "__main__":
    main()
