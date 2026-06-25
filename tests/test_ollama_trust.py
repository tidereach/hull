"""Tests for ollama_trust.py — UDS trust checks and TCP pin verification."""

from __future__ import annotations

import os
import shutil
import socket as sock_mod
import tempfile
from pathlib import Path

import httpx
import pytest
import respx


@pytest.fixture()
def sock_dir():
    """Short-path temp dir for AF_UNIX sockets.

    macOS limits socket paths to 104 bytes; pytest's tmp_path uses long paths
    under /private/var/folders/... that exceed this limit. Using /tmp directly
    keeps paths well under the limit on both Linux and macOS.
    """
    d = tempfile.mkdtemp(dir="/tmp", prefix="sk_")
    os.chmod(d, 0o700)
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# UDS trust: _socket_stat_ok
# ---------------------------------------------------------------------------


def test_uds_happy_path(sock_dir):
    """Valid UDS (S_ISSOCK, owner==EUID, mode 0600, owner-only parent) must be accepted."""
    from spektralia.ollama_trust import _socket_stat_ok

    sock_path = sock_dir / "ollama.sock"
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)
    try:
        assert _socket_stat_ok(str(sock_path)) is True
    finally:
        s.close()


def test_uds_owner_mismatch_rejected(sock_dir, monkeypatch):
    """UDS owned by another user must be rejected."""
    from spektralia.ollama_trust import _socket_stat_ok

    sock_path = sock_dir / "ollama.sock"
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)

    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    try:
        assert _socket_stat_ok(str(sock_path)) is False
    finally:
        s.close()


def test_uds_mode_0644_rejected(sock_dir):
    """UDS with mode 0644 (group/world readable) must be rejected."""
    from spektralia.ollama_trust import _socket_stat_ok

    sock_path = sock_dir / "ollama.sock"
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.bind(str(sock_path))
    os.chmod(str(sock_path), 0o644)
    try:
        assert _socket_stat_ok(str(sock_path)) is False
    finally:
        s.close()


def test_uds_world_writable_parent_rejected(sock_dir):
    """UDS in a world-writable parent directory must be rejected."""
    from spektralia.ollama_trust import _socket_stat_ok

    parent = sock_dir / "public"
    parent.mkdir(mode=0o777)
    sock_path = parent / "ollama.sock"
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)
    try:
        assert _socket_stat_ok(str(sock_path)) is False
    finally:
        s.close()


def test_uds_missing_file_rejected(tmp_path):
    """Non-existent path must be rejected."""
    from spektralia.ollama_trust import _socket_stat_ok

    assert _socket_stat_ok(str(tmp_path / "nonexistent.sock")) is False


# ---------------------------------------------------------------------------
# UDS trust: build_client raises on untrusted socket
# ---------------------------------------------------------------------------


def test_build_client_raises_on_untrusted_uds(sock_dir):
    """build_client with untrusted UDS must raise RuntimeError."""
    from spektralia.ollama_trust import build_client

    sock_path = sock_dir / "bad.sock"
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.bind(str(sock_path))
    os.chmod(str(sock_path), 0o644)  # bad mode
    try:
        with pytest.raises(RuntimeError, match="ollama_socket_untrusted"):
            build_client(
                ollama_url="http://127.0.0.1:11434",
                ollama_socket=str(sock_path),
                auth_header=None,
                model="llama3.2:3b",
            )
    finally:
        s.close()


# ---------------------------------------------------------------------------
# TCP pin: _pin_tcp
# ---------------------------------------------------------------------------


@respx.mock
def test_tcp_pin_change_raises(monkeypatch):
    """When the TCP listener PID changes, _pin_tcp must raise RuntimeError."""
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _pin_tcp, reset_pin

    reset_pin()

    # Mock /api/version to return a stable version
    respx.get("http://127.0.0.1:11434/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.1.0"})
    )

    # Patch _find_listener_pid to return PID 1000 then PID 1001
    call_count = {"n": 0}

    def fake_pid(port):
        call_count["n"] += 1
        return 1000 if call_count["n"] == 1 else 1001

    monkeypatch.setattr(ot, "_find_listener_pid", fake_pid)
    monkeypatch.setattr(ot, "_binary_hash", lambda pid: f"hash_{pid}")

    client = httpx.Client(base_url="http://127.0.0.1:11434")
    # First call pins pid=1000
    _pin_tcp(client, "http://127.0.0.1:11434")

    # Second call: pid=1001 → mismatch → RuntimeError
    with pytest.raises(RuntimeError, match="ollama_identity_changed"):
        _pin_tcp(client, "http://127.0.0.1:11434")

    reset_pin()


@respx.mock
def test_tcp_binary_hash_mismatch_raises(monkeypatch):
    """When the binary SHA-256 changes, _pin_tcp must raise RuntimeError."""
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _pin_tcp, reset_pin

    reset_pin()

    respx.get("http://127.0.0.1:11434/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.1.0"})
    )

    call_count = {"n": 0}

    def fake_hash(pid):
        call_count["n"] += 1
        return "aaa111" if call_count["n"] == 1 else "bbb222"

    monkeypatch.setattr(ot, "_find_listener_pid", lambda port: 1000)
    monkeypatch.setattr(ot, "_binary_hash", fake_hash)

    client = httpx.Client(base_url="http://127.0.0.1:11434")
    _pin_tcp(client, "http://127.0.0.1:11434")

    with pytest.raises(RuntimeError, match="ollama_identity_changed"):
        _pin_tcp(client, "http://127.0.0.1:11434")

    reset_pin()


@respx.mock
def test_tcp_version_change_raises(monkeypatch):
    """When the Ollama version string changes, _pin_tcp must raise RuntimeError."""
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _pin_tcp, reset_pin

    reset_pin()

    call_count = {"n": 0}

    def fake_version(*args, **kwargs):
        call_count["n"] += 1
        v = "0.1.0" if call_count["n"] == 1 else "0.2.0"
        return httpx.Response(200, json={"version": v})

    respx.get("http://127.0.0.1:11434/api/version").mock(side_effect=fake_version)

    monkeypatch.setattr(ot, "_find_listener_pid", lambda port: 1000)
    monkeypatch.setattr(ot, "_binary_hash", lambda pid: "stable_hash")

    client = httpx.Client(base_url="http://127.0.0.1:11434")
    _pin_tcp(client, "http://127.0.0.1:11434")

    with pytest.raises(RuntimeError, match="ollama_identity_changed"):
        _pin_tcp(client, "http://127.0.0.1:11434")

    reset_pin()


@respx.mock
def test_tcp_stable_pin_does_not_raise(monkeypatch):
    """Multiple calls with the same PID/hash/version must not raise."""
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _pin_tcp, reset_pin

    reset_pin()

    respx.get("http://127.0.0.1:11434/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.1.0"})
    )

    monkeypatch.setattr(ot, "_find_listener_pid", lambda port: 1000)
    monkeypatch.setattr(ot, "_binary_hash", lambda pid: "stable_hash")

    client = httpx.Client(base_url="http://127.0.0.1:11434")
    # Both calls should succeed without raising
    _pin_tcp(client, "http://127.0.0.1:11434")
    _pin_tcp(client, "http://127.0.0.1:11434")

    reset_pin()
