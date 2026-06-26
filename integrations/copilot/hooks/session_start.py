#!/usr/bin/env python3
"""Copilot SessionStart hook — integrity checks before the agent session."""

from __future__ import annotations

import subprocess

from _common import continue_, emit, load_claude_hook, read_payload, stop


def _run_check(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ok = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        return ok, output
    except Exception as e:
        return False, str(e)


def _emit_hook_identity(payload: dict) -> None:
    try:
        load_claude_hook("session_start")._emit_hook_identity(payload)
    except Exception:
        pass


def handle(payload: dict) -> dict:
    _emit_hook_identity(payload)
    failures: list[str] = []

    checks = [
        (["spektralia", "verify-integrity"], "verify-integrity"),
        (["spektralia", "self-test"], "self-test"),
        (["spektralia", "verify-installed"], "verify-installed"),
        (["spektralia", "check-sandbox"], "check-sandbox"),
    ]

    for cmd, name in checks:
        ok, output = _run_check(cmd)
        if not ok:
            failures.append(f"{name}: {output}")

    if failures:
        return stop("Spektralia session start checks failed:\n" + "\n".join(failures))
    return continue_()


def main() -> None:
    emit(handle(read_payload()))


if __name__ == "__main__":
    main()
