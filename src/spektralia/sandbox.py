"""Execution-plane sandbox preflight.

Spektralia is the data plane of a layered endpoint stack (see docs/ENDPOINT_STACK.md
and docs/SANDBOX_ALTERNATIVES.md). The execution plane is provided by a neighbor
sandbox — Fence or cplt — that Spektralia does not control but can assert is present.

This module realizes the "cross-layer integrity" roadmap item: confirm the configured
sandbox wrapper is on PATH and, optionally, that its config hash matches a pinned value.

Detect-only by default (sandbox_config_hash=None): assert the wrapper exists and report
the current config hash without ever blocking on drift. Hash-pinning is opt-in for
high-assurance endpoints — committed config like .cplt.toml is designed to evolve, so a
default-on pin would block sessions on every legitimate bump.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

# Resolve the infra/sandbox tree relative to this source file.
# Assumes an editable install from the repo root (standard for dev use).
_REPO_ROOT = Path(__file__).parent.parent.parent


def _cplt_sndbx_config_paths() -> tuple[str, ...]:
    """Canonical config paths for the cplt-sndbx backend."""
    base = _REPO_ROOT / "infra" / "sandbox"
    return (
        str(base / "docker-compose.yml"),
        str(base / "proxy" / "squid.conf"),
        str(base / "landlock" / "agent.policy"),
    )


# Default config files whose contents are hashed, per backend. Operators may override
# via Settings.sandbox_config_paths. Missing files are simply skipped.
_DEFAULT_CONFIG_PATHS: dict[str, tuple[str, ...]] = {
    "cplt": (".cplt.toml", "~/.config/cplt/config.toml"),
    "fence": ("~/.config/fence/profile.toml",),
    "cplt-sndbx": (),  # populated dynamically via _cplt_sndbx_config_paths()
}


def _config_hash(paths: tuple[str, ...]) -> str:
    """SHA-256 over the concatenated contents of existing config files.

    Files are hashed in the given order; missing files contribute nothing. An empty
    set of existing files yields the hash of the empty string.
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


def _check_cplt_sndbx(settings) -> tuple[bool, str]:
    """Preflight for the cplt-sndbx compose-stack backend.

    Checks:
      1. podman or docker is on PATH (offline bypass: SPEKTRALIA_SANDBOX_OFFLINE=1).
      2. The bundled compose/proxy/policy files exist and hash matches any pinned value.

    Runtime stack-is-running detection is omitted — that varies by cwd and
    compose-tool version, adding flakiness with no meaningful policy signal.
    """
    if os.environ.get("SPEKTRALIA_SANDBOX_OFFLINE", "").lower() in ("1", "true", "yes"):
        return True, "cplt-sndbx offline mode (SPEKTRALIA_SANDBOX_OFFLINE set)"

    runtime = shutil.which("podman") or shutil.which("docker")
    if runtime is None:
        return False, "cplt-sndbx: neither podman nor docker found on PATH"

    paths = settings.sandbox_config_paths or _cplt_sndbx_config_paths()
    found = [p for p in paths if Path(p).expanduser().is_file()]
    if not found:
        return False, "cplt-sndbx: infra/sandbox config files not found (run from repo root)"

    current = _config_hash(paths)
    pinned = settings.sandbox_config_hash
    if pinned and pinned != current:
        return False, f"cplt-sndbx config hash drift (pinned {pinned[:12]}, found {current[:12]})"

    runtime_name = Path(runtime).name
    return True, f"cplt-sndbx ready ({runtime_name} present), config {current[:12]}"


def check_sandbox(settings) -> tuple[bool, str]:
    """Return (ok, message) for the configured execution-plane sandbox.

    - backend "none": always ok (no sandbox configured).
    - backend "cplt-sndbx": compose-stack preflight (see _check_cplt_sndbx).
    - other backends: wrapper not on PATH → fail; config hash drift → fail.
    """
    backend = settings.sandbox_backend
    if backend == "none":
        return True, "no sandbox configured"

    if backend == "cplt-sndbx":
        return _check_cplt_sndbx(settings)

    if shutil.which(backend) is None:
        return False, f"{backend} not on PATH"

    paths = settings.sandbox_config_paths or _DEFAULT_CONFIG_PATHS.get(backend, ())
    found = [p for p in paths if Path(p).expanduser().is_file()]
    current = _config_hash(paths)

    pinned = settings.sandbox_config_hash
    if pinned and pinned != current:
        return False, f"{backend} config hash drift (pinned {pinned[:12]}, found {current[:12]})"

    if not found:
        # Wrapper is present but no policy file was located — report it plainly rather than
        # printing the hash of empty input, which would read as "config exists".
        return True, f"{backend} present, no config files found"

    return True, f"{backend} present, config {current[:12]}"
