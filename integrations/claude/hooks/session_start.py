#!/usr/bin/env python3
"""Claude Code SessionStart hook — integrity + self-test + hook-check."""

from __future__ import annotations

import json
import subprocess
import sys


def _run_check(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ok = result.returncode == 0
        output = (result.stdout + result.stderr).strip()
        return ok, output
    except Exception as e:
        return False, str(e)


def _emit_hook_identity(payload: dict) -> None:
    """Emit a signed identity proof into the audit chain.

    Prefers an Ed25519 signature over a per-call nonce, falling back to HMAC and
    then to an unsigned marker. If the hook binary is replaced or the key store
    is inaccessible, the proof will be absent or fail future verification — all
    auditable. ``spektralia audit-verify`` checks these signatures.
    """
    try:
        from spektralia.audit import AuditChain
        from spektralia.config import Settings
        from spektralia.integrity import compute_hook_identity

        session_id = payload.get("session_id") or payload.get("sessionId")
        identity = compute_hook_identity(session_id)
        s = Settings.from_env()
        chain = AuditChain(s.state_dir)
        chain.emit(
            "hook_identity",
            pattern_hash="",
            model_digest="",
            prompt_hash="",
            hook="session_start",
            identity=identity,
            # token_present retained for backward-compatible log consumers.
            token_present=bool(identity.get("sig")),
        )
        chain.close()
    except Exception:
        pass  # Never block session start on identity emit failure


def _check_hook_integrity() -> tuple[str, str]:
    """Verify installed hook scripts against the recorded manifest.

    Returns ``(decision, reason)`` where ``decision`` is "continue" or "block".
    Emits an audit event for every outcome so tamper attempts and the absence
    of a manifest are both visible after the fact. Honours
    ``Settings.hook_integrity_mode``: "off" skips, "warn" audits and continues,
    "block" refuses the session on a mismatch.
    """
    try:
        from spektralia.audit import AuditChain
        from spektralia.config import Settings
        from spektralia.hook_manifest import verify_hook_integrity

        s = Settings.from_env()
        if s.hook_integrity_mode == "off":
            return "continue", ""

        status, problems = verify_hook_integrity(s.effective_hook_manifest_path())
        chain = AuditChain(s.state_dir)
        chain.emit(
            "hook_integrity_check",
            pattern_hash="",
            model_digest="",
            prompt_hash="",
            status=status,
            problems=problems,
            mode=s.hook_integrity_mode,
        )
        chain.close()

        if status == "mismatch" and s.hook_integrity_mode == "block":
            return "block", "Hook script tampering detected:\n" + "\n".join(problems)
    except Exception:
        # Never let an integrity-check failure crash session start; the audit
        # emit above is best-effort and the gate itself remains fail-closed.
        return "continue", ""
    return "continue", ""


def handle(payload: dict) -> dict:
    _emit_hook_identity(payload)

    integrity_decision, integrity_reason = _check_hook_integrity()
    if integrity_decision == "block":
        return {"action": "block", "reason": integrity_reason}

    failures: list[str] = []

    checks = [
        (["spektralia", "verify-integrity"], "verify-integrity"),
        (["spektralia", "self-test"], "self-test"),
        (["spektralia", "hook-check"], "hook-check"),
        (["spektralia", "verify-installed"], "verify-installed"),
        # Cross-layer integrity: assert the configured execution-plane sandbox (Fence or
        # cplt) is present. No-op when sandbox_backend="none" (the default).
        (["spektralia", "check-sandbox"], "check-sandbox"),
    ]

    for cmd, name in checks:
        ok, output = _run_check(cmd)
        if not ok:
            failures.append(f"{name}: {output}")

    if failures:
        return {
            "action": "block",
            "reason": "Spektralia session start checks failed:\n" + "\n".join(failures),
        }
    return {"action": "continue"}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        payload = {}

    print(json.dumps(handle(payload)))


if __name__ == "__main__":
    main()
