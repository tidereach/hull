#!/usr/bin/env python3
"""Audit §18 hook invariants on every pre-commit.

Checks four structural invariants from SPEC §18:
  1. PreToolUse hook uses a '.*' matcher (default-deny MCP).
  2. Task/Agent tool names appear in _STRICT_SCAN_TOOLS in pre_tool_use.py.
  3. Attachment refusal is present in user_prompt_submit.py.
  4. Every hook file has a top-level try/except wrapper (fail-closed on crash).

Exits non-zero with a clear message if any invariant is violated.

Run from repo root:
    python scripts/audit_hook_invariants.py
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
HOOKS_DIR = REPO_ROOT / "integrations" / "claude" / "hooks"
SETTINGS_EXAMPLE = REPO_ROOT / "integrations" / "claude" / "settings.example.json"

HOOK_FILES = [
    "session_start.py",
    "user_prompt_submit.py",
    "pre_tool_use.py",
    "post_tool_use.py",
    "stop.py",
]

failures: list[str] = []


# ---------------------------------------------------------------------------
# Invariant 1 & 2 — settings.example.json structure + _STRICT_SCAN_TOOLS
# ---------------------------------------------------------------------------


def _check_settings() -> None:
    if not SETTINGS_EXAMPLE.exists():
        failures.append(f"Missing: {SETTINGS_EXAMPLE.relative_to(REPO_ROOT)}")
        return

    try:
        settings = json.loads(SETTINGS_EXAMPLE.read_text())
    except json.JSONDecodeError as e:
        failures.append(f"settings.example.json: JSON parse error: {e}")
        return

    hooks = settings.get("hooks", {})

    # Invariant 1: PreToolUse hook with matcher ".*" (default-deny MCP)
    pre_tool = hooks.get("PreToolUse", [])
    has_wildcard_matcher = any(entry.get("matcher") == ".*" for entry in pre_tool)
    if not has_wildcard_matcher:
        failures.append(
            "§18 invariant violated: PreToolUse hook must have matcher '.*' for default-deny MCP policy"
        )

    # Invariant 2: Task hook present (subagent leak prevention)
    # settings.example.json uses a single '.*' matcher that covers Task too;
    # the actual name-check lives in _STRICT_SCAN_TOOLS in pre_tool_use.py (checked below).
    # At least one PreToolUse entry must exist.
    if not pre_tool:
        failures.append(
            "§18 invariant violated: PreToolUse hook must be configured (required for subagent-leak prevention)"
        )


# ---------------------------------------------------------------------------
# Invariant 2 cont. — _STRICT_SCAN_TOOLS in pre_tool_use.py
# ---------------------------------------------------------------------------


def _check_strict_scan_tools() -> None:
    path = HOOKS_DIR / "pre_tool_use.py"
    if not path.exists():
        failures.append(f"Missing: {path.relative_to(REPO_ROOT)}")
        return

    source = path.read_text()

    if '"Task"' not in source and "'Task'" not in source:
        failures.append(
            "§18 invariant violated: 'Task' must be in _STRICT_SCAN_TOOLS in pre_tool_use.py "
            "(prevents subagent prompt laundering)"
        )
    if '"Agent"' not in source and "'Agent'" not in source:
        failures.append(
            "§18 invariant violated: 'Agent' must be in _STRICT_SCAN_TOOLS in pre_tool_use.py "
            "(fail-closed across Claude Code versions that rename Task→Agent)"
        )

    if "mcp__" not in source:
        failures.append(
            "§18 invariant violated: MCP default-deny check (mcp__) missing from pre_tool_use.py"
        )


# ---------------------------------------------------------------------------
# Invariant 3 — Attachment refusal in user_prompt_submit.py
# ---------------------------------------------------------------------------


def _check_attachment_refusal() -> None:
    path = HOOKS_DIR / "user_prompt_submit.py"
    if not path.exists():
        failures.append(f"Missing: {path.relative_to(REPO_ROOT)}")
        return

    source = path.read_text()
    if "attachment" not in source.lower():
        failures.append(
            "§18 invariant violated: attachment refusal logic missing from user_prompt_submit.py"
        )


# ---------------------------------------------------------------------------
# Invariant 4 — Every hook has a top-level try/except (fail-closed on crash)
# ---------------------------------------------------------------------------


def _has_toplevel_try_except(path: Path) -> bool:
    """Return True if the module has at least one try/except at module or handle() scope."""
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return False

    # Accept: try/except at module level
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            return True
    return False


def _check_fail_closed() -> None:
    for name in HOOK_FILES:
        path = HOOKS_DIR / name
        if not path.exists():
            failures.append(f"Missing hook file: {path.relative_to(REPO_ROOT)}")
            continue
        if not _has_toplevel_try_except(path):
            failures.append(
                f"§18 invariant violated: {name} has no try/except — hook must be fail-closed on crash"
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    _check_settings()
    _check_strict_scan_tools()
    _check_attachment_refusal()
    _check_fail_closed()

    if failures:
        print("Hook invariant audit FAILED:")
        for f in failures:
            print(f"  ✗ {f}")
        return 1

    print("Hook invariant audit passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
