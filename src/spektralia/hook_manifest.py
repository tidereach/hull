"""Hook script integrity manifest.

Records SHA-256 digests of installed hook scripts at ``install-hooks`` time so
that post-install tampering can be detected at ``SessionStart``. This is the
hash-based foundation; the stronger Ed25519 call-time identity proof (see
``integrity.compute_hook_token`` and the keyring-backed signer) builds on top.

The manifest is a plain JSON file under the state dir (mode 0600). It stores the
absolute ``hooks_dir`` it was generated from plus a digest per ``*.py`` hook, so
the SessionStart check can recompute digests against the same directory without
re-resolving it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

MANIFEST_VERSION = 1

# The hook scripts Spektralia installs. Only these files are tracked; an
# unrelated *.py dropped into the hooks dir is never wired into settings.json,
# so it cannot run and is out of scope for this check.
HOOK_FILENAMES = (
    "session_start.py",
    "user_prompt_submit.py",
    "pre_tool_use.py",
    "post_tool_use.py",
    "stop.py",
)


def _digest_file(path: Path) -> str:
    """SHA-256 hex digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_hook_digests(hooks_dir: Path) -> dict[str, str]:
    """Map each present hook filename to its SHA-256 digest.

    Files listed in ``HOOK_FILENAMES`` that are absent are simply omitted, so a
    later comparison surfaces them as missing rather than raising here.
    """
    digests: dict[str, str] = {}
    for name in HOOK_FILENAMES:
        fpath = hooks_dir / name
        if fpath.is_file():
            digests[name] = _digest_file(fpath)
    return digests


def write_manifest(manifest_path: Path, hooks_dir: Path) -> dict:
    """Compute digests for ``hooks_dir`` and persist a manifest at ``manifest_path``.

    Returns the manifest dict that was written. The file is created with mode
    0600 (owner read/write only).
    """
    manifest = {
        "version": MANIFEST_VERSION,
        "hooks_dir": str(hooks_dir.resolve()),
        "digests": compute_hook_digests(hooks_dir),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    # Write then tighten mode (umask may clear bits on create).
    manifest_path.write_text(serialized)
    try:
        os.chmod(manifest_path, 0o600)
    except OSError:  # pragma: no cover - non-POSIX or permission edge
        pass
    return manifest


def read_manifest(manifest_path: Path) -> dict | None:
    """Load a manifest, or ``None`` if it does not exist or is unreadable."""
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def verify_hook_integrity(manifest_path: Path) -> tuple[str, list[str]]:
    """Compare on-disk hook scripts against a stored manifest.

    Returns ``(status, problems)`` where ``status`` is one of:

    - ``"no_manifest"`` — no manifest recorded (install-hooks never run, or the
      file was removed). ``problems`` is empty; callers decide whether the
      absence is itself notable.
    - ``"ok"`` — every recorded digest matches the current file.
    - ``"mismatch"`` — at least one file is missing or its digest changed;
      ``problems`` lists each discrepancy.
    """
    manifest = read_manifest(manifest_path)
    if manifest is None:
        return "no_manifest", []

    hooks_dir = Path(manifest.get("hooks_dir", ""))
    recorded: dict[str, str] = manifest.get("digests", {})

    problems: list[str] = []
    for name, expected in recorded.items():
        fpath = hooks_dir / name
        if not fpath.is_file():
            problems.append(f"{name}: missing (expected at {fpath})")
            continue
        actual = _digest_file(fpath)
        if actual != expected:
            problems.append(
                f"{name}: digest mismatch (expected {expected[:12]}…, got {actual[:12]}…)"
            )

    status = "ok" if not problems else "mismatch"
    return status, problems
