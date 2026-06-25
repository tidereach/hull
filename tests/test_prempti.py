"""Tests for the control-plane (Prempti) preflight (spektralia.prempti)."""

from __future__ import annotations

import socket

from spektralia.config import Settings
from spektralia.prempti import _config_hash, check_prempti


def test_backend_none_is_ok():
    ok, msg = check_prempti(Settings(prempti_backend="none"))
    assert ok
    assert "no control plane" in msg


def test_backend_set_but_missing_binary_fails(monkeypatch):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: None)
    ok, msg = check_prempti(Settings(prempti_backend="prempti"))
    assert not ok
    assert "not on PATH" in msg


def test_present_binary_no_socket_detect_only_is_ok(monkeypatch):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    s = Settings(prempti_backend="prempti", prempti_config_paths=())
    ok, msg = check_prempti(s)
    assert ok
    assert "prempti present" in msg


def test_present_binary_missing_socket_fails(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    not_a_socket = tmp_path / "prempti.sock"  # does not exist
    s = Settings(prempti_backend="prempti", prempti_socket=str(not_a_socket))
    ok, msg = check_prempti(s)
    assert not ok
    assert "socket not found" in msg


def test_present_binary_live_socket_is_ok(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    sock_path = tmp_path / "prempti.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    try:
        s = Settings(
            prempti_backend="prempti",
            prempti_socket=str(sock_path),
            prempti_config_paths=(),
        )
        ok, _ = check_prempti(s)
        assert ok
    finally:
        srv.close()


def test_present_binary_with_config_reports_hash(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("- rule: x\n")
    s = Settings(prempti_backend="prempti", prempti_config_paths=(str(cfg),))
    ok, msg = check_prempti(s)
    assert ok
    assert "config" in msg


def test_present_binary_no_config_reports_plainly(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    missing = tmp_path / "absent.yaml"
    s = Settings(prempti_backend="prempti", prempti_config_paths=(str(missing),))
    ok, msg = check_prempti(s)
    assert ok
    assert "no config files found" in msg


def test_present_binary_matching_pin_is_ok(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("- rule: x\n")
    paths = (str(cfg),)
    s = Settings(
        prempti_backend="prempti",
        prempti_config_paths=paths,
        prempti_config_hash=_config_hash(paths),
    )
    ok, _ = check_prempti(s)
    assert ok


def test_present_binary_mismatched_pin_fails(monkeypatch, tmp_path):
    monkeypatch.setattr("spektralia.prempti.shutil.which", lambda _name: "/usr/bin/premptictl")
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("- rule: x\n")
    s = Settings(
        prempti_backend="prempti",
        prempti_config_paths=(str(cfg),),
        prempti_config_hash="0" * 64,
    )
    ok, msg = check_prempti(s)
    assert not ok
    assert "drift" in msg


def test_config_hash_changes_with_content(tmp_path):
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("a")
    h1 = _config_hash((str(cfg),))
    cfg.write_text("b")
    h2 = _config_hash((str(cfg),))
    assert h1 != h2
