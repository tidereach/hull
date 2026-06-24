#!/usr/bin/env python3
"""Claude Code SessionStart hook — integrity + self-test + hook-check."""
from __future__ import annotations

import json
import subprocess
import sys


def run_check(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ok = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        return ok, output
    except Exception as e:
        return False, str(e)


def main() -> None:
    failures: list[str] = []

    checks = [
        (["spektralia", "verify-integrity"], "verify-integrity"),
        (["spektralia", "self-test"], "self-test"),
        (["spektralia", "hook-check"], "hook-check"),
        (["spektralia", "verify-installed"], "verify-installed"),
    ]

    for cmd, name in checks:
        ok, output = run_check(cmd)
        if not ok:
            failures.append(f"{name}: {output}")

    if failures:
        print(json.dumps({
            "action": "block",
            "reason": "Spektralia session start checks failed:\n" + "\n".join(failures),
        }))
    else:
        print(json.dumps({"action": "continue"}))


if __name__ == "__main__":
    main()
