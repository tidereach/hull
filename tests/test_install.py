"""Tests for automated hook installation (spektralia.install)."""

from __future__ import annotations

import json
import stat

import pytest

from spektralia.install import (
    _SPEKTRALIA_HOOKS,
    install_hooks,
    render_hooks,
    repo_root,
    settings_path,
)


def test_repo_root_contains_integrations():
    root = repo_root()
    assert (root / "integrations" / "claude_code_hooks" / "settings.example.json").is_file()


def test_render_hooks_substitutes_placeholder():
    root = repo_root()
    hooks = render_hooks(root)
    # All five Spektralia events are present and reference the real repo root, not the placeholder.
    for event in _SPEKTRALIA_HOOKS:
        assert event in hooks
    blob = json.dumps(hooks)
    assert "/path/to/spektralia" not in blob
    assert str(root) in blob


def test_settings_path_scopes(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    assert settings_path("global") == home / ".claude" / "settings.json"
    monkeypatch.chdir(tmp_path)
    assert settings_path("project") == (tmp_path / ".claude" / "settings.json").resolve()


def test_settings_path_rejects_unknown_scope():
    with pytest.raises(ValueError, match="unknown scope"):
        settings_path("nope")


def test_install_project_writes_hooks_and_0600(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    target = install_hooks("project")
    assert target == (tmp_path / ".claude" / "settings.json").resolve()
    data = json.loads(target.read_text())
    for event in _SPEKTRALIA_HOOKS:
        assert event in data["hooks"]
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600


def test_install_preserves_unrelated_keys_and_hooks(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = claude_dir / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "model": "claude-opus-4-8",
                "hooks": {"Notification": [{"hooks": [{"type": "command", "command": "x"}]}]},
            }
        )
    )
    install_hooks("project")
    data = json.loads(settings.read_text())
    # Unrelated top-level key preserved.
    assert data["model"] == "claude-opus-4-8"
    # Unrelated hook event preserved alongside Spektralia's.
    assert "Notification" in data["hooks"]
    assert "SessionStart" in data["hooks"]


def test_install_rejects_corrupt_settings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text("{not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        install_hooks("project")


def test_install_global_scope(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    target = install_hooks("global")
    assert target == home / ".claude" / "settings.json"
    assert target.is_file()
