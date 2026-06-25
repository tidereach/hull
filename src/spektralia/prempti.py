"""Control-plane (intent policy) preflight.

Spektralia is the data plane of a layered endpoint stack (see docs/ENDPOINT_STACK.md).
The control plane — intent policy over tool calls — is provided by a neighbor service,
Prempti (a Falco rule engine), that Spektralia does not control but can assert is present.

This is the control-plane analog of ``spektralia.sandbox``: it realizes the remaining
"cross-layer integrity" item from ENDPOINT_STACK.md — assert the Prempti service is up —
the same way ``check_sandbox`` asserts the execution-plane wrapper is on PATH.

Detect-only by default (prempti_backend="none" → no-op). When enabled, the check is
fail-closed: a missing ``premptictl`` binary, an absent IPC socket, or a drifted config
pin blocks the session, matching the rest of the stack's posture.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

# Binary that fronts the Prempti service (its CLI / health entrypoint).
_PREMPTI_BIN = "premptictl"

# Default config files whose contents are hashed when a pin is set. Operators may override
# via Settings.prempti_config_paths. Missing files are simply skipped.
_DEFAULT_CONFIG_PATHS: tuple[str, ...] = (
    ".prempti.toml",
    "~/.prempti/rules.yaml",
)


def _config_hash(paths: tuple[str, ...]) -> str:
    """SHA-256 over the concatenated contents of existing config files.

    Files are hashed in the given order; missing files contribute nothing. An empty
    set of existing files yields the hash of the empty string. Mirrors
    ``spektralia.sandbox._config_hash`` so the two preflights pin config identically.
    """
    h = hashlib.sha256()
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            h.update(raw.encode())
            h.update(b"\0")
            h.update(p.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def check_prempti(settings) -> tuple[bool, str]:
    """Return (ok, message) for the configured control-plane service.

    - backend "none": always ok (no control plane configured).
    - premptictl not on PATH: fail.
    - prempti_socket set but not a live socket: fail (service down).
    - prempti_config_hash pinned and current hash differs: fail (config drift).
    - otherwise: ok, reporting the current config hash prefix when files exist.
    """
    backend = settings.prempti_backend
    if backend == "none":
        return True, "no control plane configured"

    if shutil.which(_PREMPTI_BIN) is None:
        return False, f"{_PREMPTI_BIN} not on PATH"

    socket = settings.prempti_socket
    if socket:
        sp = Path(socket).expanduser()
        if not sp.is_socket():
            return False, f"prempti socket not found at {socket}"

    paths = settings.prempti_config_paths or _DEFAULT_CONFIG_PATHS
    found = [p for p in paths if Path(p).expanduser().is_file()]
    current = _config_hash(paths)

    pinned = settings.prempti_config_hash
    if pinned and pinned != current:
        return False, f"prempti config hash drift (pinned {pinned[:12]}, found {current[:12]})"

    if not found:
        return True, "prempti present, no config files found"

    return True, f"prempti present, config {current[:12]}"
