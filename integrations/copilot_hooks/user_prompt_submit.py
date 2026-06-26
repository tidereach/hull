#!/usr/bin/env python3
"""Copilot UserPromptSubmit hook — scan and block sensitive prompts."""

from __future__ import annotations

from _common import emit, load_claude_hook, read_payload, stop


def handle(payload: dict) -> dict:
    try:
        result = load_claude_hook("user_prompt_submit").handle(payload)
    except Exception as e:
        return stop(f"hook_error: {type(e).__name__}")

    if result.get("decision") == "block":
        return stop(result.get("reason", "Spektralia blocked prompt"))
    return {}


def main() -> None:
    payload = read_payload()
    if not payload:
        emit(stop("hook_input_parse_error"))
        return
    emit(handle(payload))


if __name__ == "__main__":
    main()
