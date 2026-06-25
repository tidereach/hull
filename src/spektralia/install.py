"""Automated Claude Code hook installation.

Realizes the ``spektralia install-hooks`` roadmap item (docs/PLAN.md §8): locate this
repository root, render the five Spektralia hook commands against it, and merge them into
a Claude Code ``settings.json`` — global (``~/.claude/settings.json``) or project-scoped
(``<cwd>/.claude/settings.json``) — without clobbering unrelated configuration.

The rendered block is derived from
``integrations/claude_code_hooks/settings.example.json`` so the example and the installer
never drift: only the ``/path/to/spektralia`` placeholder is substituted. Existing,
non-Spektralia hooks and top-level keys are preserved; only the five hook events Spektralia
owns are (re)written.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_PLACEHOLDER = "/path/to/spektralia"

# The hook events Spektralia owns. Only these are (re)written on install; any other hooks
# the user has configured are preserved.
_SPEKTRALIA_HOOKS = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
)


def repo_root() -> Path:
    """Absolute path to the spektralia repository root (parent of ``src/``)."""
    # install.py lives at <root>/src/spektralia/install.py
    return Path(__file__).resolve().parents[2]


def _example_path(root: Path) -> Path:
    return root / "integrations" / "claude_code_hooks" / "settings.example.json"


def render_hooks(root: Path) -> dict:
    """Load the example settings and substitute the repo-root placeholder."""
    raw = _example_path(root).read_text()
    raw = raw.replace(_PLACEHOLDER, str(root))
    hooks: dict = json.loads(raw)["hooks"]
    return hooks


def settings_path(scope: str) -> Path:
    """Resolve the target settings.json for the given scope ('global' | 'project')."""
    if scope == "global":
        return Path.home() / ".claude" / "settings.json"
    if scope == "project":
        return (Path.cwd() / ".claude" / "settings.json").resolve()
    raise ValueError(f"unknown scope {scope!r} (expected 'global' or 'project')")


def install_hooks(scope: str = "project", *, root: Path | None = None) -> Path:
    """Merge Spektralia's hooks into the scoped settings.json and return its path.

    Preserves any existing top-level keys and any non-Spektralia hook events; replaces
    only the five events Spektralia owns. The file is written with mode 0600.
    """
    root = root or repo_root()
    target = settings_path(scope)
    target.parent.mkdir(parents=True, exist_ok=True)

    existing: dict = {}
    if target.exists():
        try:
            existing = json.loads(target.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"{target} is not valid JSON: {e}") from e

    hooks = dict(existing.get("hooks", {}))
    rendered = render_hooks(root)
    for event in _SPEKTRALIA_HOOKS:
        if event in rendered:
            hooks[event] = rendered[event]
    existing["hooks"] = hooks

    target.write_text(json.dumps(existing, indent=2) + "\n")
    os.chmod(target, 0o600)
    return target
