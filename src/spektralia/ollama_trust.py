from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import stat
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TCP_PIN: dict[str, Any] = {}  # pid, binary_hash, version


def _socket_stat_ok(path: str) -> bool:
    """Verify UDS ownership, mode, and parent directory."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISSOCK(st.st_mode):
        logger.error("ollama_trust: %s is not a socket", path)
        return False
    if st.st_uid != os.getuid():
        logger.error("ollama_trust: %s not owned by current user", path)
        return False
    if stat.S_IMODE(st.st_mode) != 0o600:
        logger.error("ollama_trust: %s mode is not 0600", path)
        return False
    parent = str(Path(path).parent)
    try:
        pst = os.lstat(parent)
    except FileNotFoundError:
        return False
    if pst.st_uid != os.getuid() or (pst.st_mode & 0o077):
        logger.error("ollama_trust: parent dir %s is not owner-only", parent)
        return False
    return True


def _binary_hash(pid: int) -> str | None:
    if platform.system() != "Linux":
        return None
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        with open(exe, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def _find_listener_pid(port: int) -> int | None:
    """Find PID listening on TCP port (Linux /proc/net/tcp only)."""
    if platform.system() != "Linux":
        return None
    try:
        hex_port = f"{port:04X}"
        with open("/proc/net/tcp") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_addr = parts[1]
                state = parts[3]
                inode = parts[9]
                if ":" not in local_addr:
                    continue
                _, lport = local_addr.split(":")
                if lport.upper() == hex_port and state == "0A":  # LISTEN
                    # Find process owning this inode
                    inode_target = f"socket:[{inode}]"
                    for pid_dir in Path("/proc").iterdir():
                        if not pid_dir.name.isdigit():
                            continue
                        try:
                            for fd in (pid_dir / "fd").iterdir():
                                if os.readlink(str(fd)) == inode_target:
                                    return int(pid_dir.name)
                        except (PermissionError, FileNotFoundError):
                            continue
    except OSError:
        pass
    return None


def build_client(
    ollama_url: str,
    ollama_socket: str | None,
    auth_header: str | None,
    model: str,
) -> httpx.Client:
    """Build an httpx.Client with appropriate transport and verify trust."""
    headers = {}
    if auth_header:
        headers["Authorization"] = f"Bearer {auth_header}"

    if ollama_socket:
        if not _socket_stat_ok(ollama_socket):
            raise RuntimeError(
                f"ollama_socket_untrusted: {ollama_socket} failed ownership/mode check"
            )
        transport = httpx.HTTPTransport(uds=ollama_socket)
        client = httpx.Client(
            base_url="http://localhost",
            transport=transport,
            headers=headers,
            timeout=30.0,
        )
    else:
        client = httpx.Client(
            base_url=ollama_url,
            headers=headers,
            timeout=30.0,
        )
        _pin_tcp(client, ollama_url)

    return client


def _pin_tcp(client: httpx.Client, url: str) -> None:
    """Pin the TCP listener PID and binary hash on first use."""
    global _TCP_PIN
    try:
        resp = client.get("/api/version")
        version = resp.json().get("version", "unknown")
    except Exception as e:
        raise RuntimeError(f"Cannot reach Ollama at {url}: {e}") from e

    # Extract port from URL
    m = re.search(r":(\d+)", url)
    port = int(m.group(1)) if m else 11434

    pid = _find_listener_pid(port)
    binary_hash = _binary_hash(pid) if pid else None

    if not _TCP_PIN:
        _TCP_PIN = {"pid": pid, "binary_hash": binary_hash, "version": version}
        logger.info("ollama_trust: TCP pin set pid=%s hash=%s", pid, binary_hash)
    else:
        if (
            _TCP_PIN["pid"] != pid
            or _TCP_PIN["binary_hash"] != binary_hash
            or _TCP_PIN["version"] != version
        ):
            raise RuntimeError(
                f"ollama_identity_changed: expected {_TCP_PIN}, got pid={pid} "
                f"hash={binary_hash} version={version}"
            )


def reset_pin() -> None:
    """Reset TCP pin (call on process restart or for testing)."""
    global _TCP_PIN
    _TCP_PIN = {}
