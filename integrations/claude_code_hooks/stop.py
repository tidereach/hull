#!/usr/bin/env python3
"""Claude Code Stop hook — emit session_end audit roll-up."""

from __future__ import annotations

import json
import sys


def handle(payload: dict) -> dict:
    try:
        from spektralia.audit import AuditChain
        from spektralia.config import Settings

        s = Settings.from_env()
        chain = AuditChain(s.state_dir)
        chain.emit("session_end", pattern_hash="", model_digest="", prompt_hash="")
        chain.close()
    except Exception:
        pass  # Don't block session termination on audit errors

    return {"action": "continue"}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        payload = {}

    print(json.dumps(handle(payload)))


if __name__ == "__main__":
    main()
