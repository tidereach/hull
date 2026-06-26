#!/usr/bin/env python3
"""Copilot Stop hook — emit session-end audit event."""

from __future__ import annotations

from _common import continue_, emit, load_claude_hook, read_payload


def handle(payload: dict) -> dict:
    try:
        load_claude_hook("stop").handle(payload)
    except Exception:
        pass
    return continue_()


def main() -> None:
    emit(handle(read_payload()))


if __name__ == "__main__":
    main()
