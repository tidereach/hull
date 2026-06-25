"""Tests for the execution-plane sandbox preflight (spektralia.sandbox)."""

from __future__ import annotations

from spektralia.config import Settings
from spektralia.sandbox import _config_hash, check_sandbox


def test_backend_none_is_ok():
    ok, msg = check_sandbox(Settings(sandbox_backend="none"))
    assert ok
    assert "no sandbox" in msg


def test_backend_set_but_missing_binary_fails(monkeypatch):
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _name: None)
    ok, msg = check_sandbox(Settings(sandbox_backend="cplt"))
    assert not ok
    assert "not on PATH" in msg


def test_present_binary_detect_only_is_ok(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _name: "/usr/bin/cplt")
    cfg = tmp_path / ".cplt.toml"
    cfg.write_text("[deny]\npaths = ['~/.ssh']\n")
    s = Settings(sandbox_backend="cplt", sandbox_config_paths=(str(cfg),))
    ok, msg = check_sandbox(s)
    assert ok
    assert "cplt present" in msg


def test_present_binary_no_config_reports_plainly(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _name: "/usr/bin/cplt")
    missing = tmp_path / "absent.toml"
    s = Settings(sandbox_backend="cplt", sandbox_config_paths=(str(missing),))
    ok, msg = check_sandbox(s)
    assert ok
    assert "no config files found" in msg


def test_present_binary_matching_pin_is_ok(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _name: "/usr/bin/cplt")
    cfg = tmp_path / ".cplt.toml"
    cfg.write_text("[deny]\npaths = ['~/.ssh']\n")
    paths = (str(cfg),)
    pinned = _config_hash(paths)
    s = Settings(
        sandbox_backend="cplt",
        sandbox_config_paths=paths,
        sandbox_config_hash=pinned,
    )
    ok, _ = check_sandbox(s)
    assert ok


def test_present_binary_mismatched_pin_fails(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _name: "/usr/bin/cplt")
    cfg = tmp_path / ".cplt.toml"
    cfg.write_text("[deny]\npaths = ['~/.ssh']\n")
    s = Settings(
        sandbox_backend="cplt",
        sandbox_config_paths=(str(cfg),),
        sandbox_config_hash="0" * 64,
    )
    ok, msg = check_sandbox(s)
    assert not ok
    assert "drift" in msg


def test_config_hash_changes_with_content(tmp_path):
    cfg = tmp_path / ".cplt.toml"
    cfg.write_text("a")
    h1 = _config_hash((str(cfg),))
    cfg.write_text("b")
    h2 = _config_hash((str(cfg),))
    assert h1 != h2
