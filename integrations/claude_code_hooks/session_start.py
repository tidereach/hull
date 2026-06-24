#!/usr/bin/env python3
"""Claude Code SessionStart hook — integrity + self-test + hook-check."""
from __future__ import annotations

import json
import subprocess
import sys


def _run_check(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ok = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        return ok, output
    except Exception as e:
        return False, str(e)


def handle(payload: dict) -> dict:
    failures: list[str] = []

    checks = [
        (["spektralia", "verify-integrity"], "verify-integrity"),
        (["spektralia", "self-test"], "self-test"),
        (["spektralia", "hook-check"], "hook-check"),
        (["spektralia", "verify-installed"], "verify-installed"),
    ]

    for cmd, name in checks:
        ok, output = _run_check(cmd)
        if not ok:
            failures.append(f"{name}: {output}")

    if failures:
        return {
            "action": "block",
            "reason": "Spektralia session start checks failed:\n" + "\n".join(failures),
        }
    return {"action": "continue"}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        payload = {}

    print(json.dumps(handle(payload)))


if __name__ == "__main__":
    main()
