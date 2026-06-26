"""Shared helpers for Copilot hook adapters."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType


def read_payload(default: dict | None = None) -> dict:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        return {} if default is None else default
    return payload if isinstance(payload, dict) else ({} if default is None else default)


def emit(result: dict) -> None:
    if result:
        print(json.dumps(result))


def continue_() -> dict:
    return {"continue": True}


def stop(reason: str) -> dict:
    return {
        "continue": False,
        "stopReason": reason,
        "systemMessage": reason,
    }


def load_claude_hook(name: str) -> ModuleType:
    repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "integrations" / "claude" / "hooks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"spektralia_claude_hook_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load hook: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
