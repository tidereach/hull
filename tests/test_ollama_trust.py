"""Tests for ollama_trust.py — UDS trust checks and TCP pin verification."""

from __future__ import annotations

import os
import platform
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


@respx.mock
def test_pin_tcp_unreachable_raises(monkeypatch):
    """If Ollama can't be reached on first pin, _pin_tcp must raise RuntimeError."""
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _pin_tcp, reset_pin

    reset_pin()
    respx.get("http://127.0.0.1:11434/api/version").mock(side_effect=httpx.ConnectError("refused"))
    monkeypatch.setattr(ot, "_find_listener_pid", lambda port: 1000)
    monkeypatch.setattr(ot, "_binary_hash", lambda pid: "h")

    client = httpx.Client(base_url="http://127.0.0.1:11434")
    with pytest.raises(RuntimeError, match="Cannot reach Ollama"):
        _pin_tcp(client, "http://127.0.0.1:11434")
    reset_pin()


# ---------------------------------------------------------------------------
# _socket_stat_ok: non-socket path
# ---------------------------------------------------------------------------


def test_socket_stat_regular_file_rejected(tmp_path):
    """A regular file (not a socket) at the path must be rejected."""
    from spektralia.ollama_trust import _socket_stat_ok

    f = tmp_path / "not_a_socket"
    f.write_text("x")
    assert _socket_stat_ok(str(f)) is False


# ---------------------------------------------------------------------------
# build_client success branches (UDS transport + TCP transport)
# ---------------------------------------------------------------------------


def test_build_client_uds_success_sets_auth_header(sock_dir):
    """A trusted UDS builds a client over a uds transport and applies the auth header."""
    from spektralia.ollama_trust import build_client

    sock_path = sock_dir / "ollama.sock"
    s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
    s.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)
    try:
        client = build_client(
            ollama_url="http://127.0.0.1:11434",
            ollama_socket=str(sock_path),
            auth_header="tok123",
            model="llama3.1:8b",
        )
        try:
            assert client.headers["Authorization"] == "Bearer tok123"
        finally:
            client.close()
    finally:
        s.close()


def test_build_client_tcp_success(monkeypatch):
    """With no socket, build_client builds a TCP client and pins it."""
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import build_client

    monkeypatch.setattr(ot, "_pin_tcp", lambda client, url: None)
    client = build_client(
        ollama_url="http://127.0.0.1:11434",
        ollama_socket=None,
        auth_header="abc",
        model="llama3.1:8b",
    )
    try:
        assert str(client.base_url) == "http://127.0.0.1:11434"
        assert client.headers["Authorization"] == "Bearer abc"
    finally:
        client.close()


# ---------------------------------------------------------------------------
# _binary_hash
# ---------------------------------------------------------------------------


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux /proc only")
def test_binary_hash_self_returns_sha256():
    """_binary_hash of our own PID returns the 64-hex sha256 of the interpreter binary."""
    from spektralia.ollama_trust import _binary_hash

    h = _binary_hash(os.getpid())
    assert h is not None
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_binary_hash_non_linux_returns_none(monkeypatch):
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _binary_hash

    monkeypatch.setattr(ot.platform, "system", lambda: "Darwin")
    assert _binary_hash(os.getpid()) is None


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux /proc only")
def test_binary_hash_bad_pid_returns_none():
    """A non-existent PID yields None (readlink OSError swallowed)."""
    from spektralia.ollama_trust import _binary_hash

    assert _binary_hash(2**30) is None


# ---------------------------------------------------------------------------
# _find_listener_pid
# ---------------------------------------------------------------------------


def test_find_listener_pid_non_linux_returns_none(monkeypatch):
    import spektralia.ollama_trust as ot
    from spektralia.ollama_trust import _find_listener_pid

    monkeypatch.setattr(ot.platform, "system", lambda: "Darwin")
    assert _find_listener_pid(11434) is None


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux /proc/net/tcp only")
def test_find_listener_pid_finds_own_listener():
    """A real IPv4 listener on an ephemeral port resolves back to this process."""
    from spektralia.ollama_trust import _find_listener_pid

    srv = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
    srv.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert _find_listener_pid(port) == os.getpid()
    finally:
        srv.close()
