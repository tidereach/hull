from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_API_VERSION = 1


def cmd_scan(args: argparse.Namespace) -> int:
    from .config import Settings
    from .errors import SensitiveDataError
    from .gate import gate

    settings = Settings.from_env()
    if args.explain:
        settings.mode = "strict"  # explain always strict

    text = sys.stdin.read()
    if not text:
        return 0

    try:
        result = asyncio.run(gate(text, settings))
    except SensitiveDataError as e:
        print(str(e), file=sys.stderr)
        return 2

    if result.blocked:
        print(f"Blocked: {result.block_reason}", file=sys.stderr)
        return 2

    if args.explain:
        _print_explain(result)
    else:
        print(result.sanitized_text, end="")

    return 0


def _print_explain(result) -> None:
    print(f"Detections ({len(result.detections)}):", file=sys.stderr)
    for d in result.detections:
        print(f"  [{d.label}] span=({d.start},{d.end})", file=sys.stderr)
    if result.classifier_result:
        cr = result.classifier_result
        print(
            f"Classifier: sensitive={cr.sensitive} confidence={cr.confidence:.2f} "
            f"categories={cr.categories}",
            file=sys.stderr,
        )


def cmd_check_ollama(args: argparse.Namespace) -> int:
    from .config import Settings
    from .ollama_trust import build_client

    s = Settings.from_env()
    try:
        client = build_client(s.ollama_url, s.ollama_socket, s.ollama_auth_header, s.ollama_model)
        resp = client.get("/api/version")
        print(f"OK: Ollama {resp.json().get('version', 'unknown')}")
        return 0
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1


def cmd_check_sandbox(args: argparse.Namespace) -> int:
    from .config import Settings
    from .sandbox import check_sandbox

    s = Settings.from_env()
    ok, msg = check_sandbox(s)
    if ok:
        print(f"OK: {msg}")
        return 0
    print(f"FAIL: {msg}", file=sys.stderr)
    return 1


def cmd_verify_integrity(args: argparse.Namespace) -> int:
    from .config import Settings
    from .integrity import get_integrity_report

    s = Settings.from_env()
    report = get_integrity_report(None, s.ollama_model)
    report["model_digest"] = s.ollama_model_digest or ""
    for k, v in report.items():
        print(f"{k}: {v}")
    return 0


def cmd_verify_installed(args: argparse.Namespace) -> int:
    from .integrity import verify_installed

    lock_path = Path("requirements.lock")
    problems = verify_installed(lock_path)
    if problems:
        for p in problems:
            print(f"DRIFT: {p}", file=sys.stderr)
        return 1
    print("OK: dependencies match requirements.lock")
    return 0


def cmd_self_test(args: argparse.Namespace) -> int:
    from .canary import run_canary
    from .scanner import scan

    result = run_canary(scan)
    if result.passed:
        print(f"OK: all canary cases passed ({result.duration_seconds:.2f}s)")
        return 0
    for f in result.failures:
        print(f"FAIL: {f}", file=sys.stderr)
    return 1


def cmd_stats(args: argparse.Namespace) -> int:
    from .anomaly import FreezeSwitch
    from .config import Settings

    s = Settings.from_env()
    frozen, reason = FreezeSwitch(s.freeze_path).is_frozen()
    print(f"frozen: {frozen}" + (f" ({reason})" if reason else ""))
    return 0


def cmd_freeze(args: argparse.Namespace) -> int:
    from .anomaly import FreezeSwitch
    from .config import Settings

    s = Settings.from_env()
    FreezeSwitch(s.freeze_path).set_frozen(True)
    print("Gate frozen.")
    return 0


def cmd_unfreeze(args: argparse.Namespace) -> int:
    from .anomaly import FreezeSwitch
    from .config import Settings

    s = Settings.from_env()
    FreezeSwitch(s.freeze_path).set_frozen(False)
    print("Gate unfrozen.")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from .audit import AuditChain

    try:
        records = []
        with open(args.path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

        from .config import Settings

        s = Settings.from_env()
        chain = AuditChain(s.state_dir)
        broken = chain.verify(records)
        if broken:
            print(f"CHAIN BROKEN at indices: {broken}", file=sys.stderr)
            return 1
        print(f"OK: {len(records)} records, chain intact")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_audit_rotate(args: argparse.Namespace) -> int:
    from .audit import AuditChain
    from .config import Settings

    s = Settings.from_env()
    chain = AuditChain(s.state_dir)
    removed = chain.rotate(args.keep_days)
    chain.close()
    print(f"OK: rotated audit log — {removed} record(s) removed (keep_days={args.keep_days})")
    return 0


def cmd_audit_purge(args: argparse.Namespace) -> int:
    from .audit import AuditChain
    from .config import Settings

    s = Settings.from_env()
    chain = AuditChain(s.state_dir)
    try:
        removed = chain.purge(args.before)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        chain.close()
        return 1
    chain.close()
    print(f"OK: purged audit log — {removed} record(s) removed (before={args.before})")
    return 0


def cmd_scan_config(args: argparse.Namespace) -> int:
    """Scan CLAUDE.md files for sensitive content."""
    from .scanner import scan

    paths = list(Path(".").rglob("CLAUDE.md")) + list(Path.home().glob(".claude/CLAUDE.md"))
    found_issues = False
    for path in paths:
        try:
            text = path.read_text()
            detections = scan(text)
            if detections:
                found_issues = True
                for d in detections:
                    print(f"WARN: {path}: [{d.label}] at ({d.start},{d.end})", file=sys.stderr)
        except OSError:
            pass
    return 1 if found_issues else 0


def cmd_hook_check(args: argparse.Namespace) -> int:
    """Check Claude Code hooks are installed (global or project settings)."""
    candidates = [
        (Path(".claude") / "settings.json").resolve(),
        Path.home() / ".claude" / "settings.json",
    ]
    hook_sources: dict[str, str] = {}  # hook_name -> settings file it was found in
    checked: list[str] = []
    for settings_path in candidates:
        if not settings_path.exists():
            continue
        try:
            data = json.loads(settings_path.read_text())
            for hook_name in data.get("hooks", {}).keys():
                if hook_name not in hook_sources:
                    hook_sources[hook_name] = str(settings_path)
            checked.append(str(settings_path))
        except Exception as e:
            print(f"Error reading {settings_path}: {e}", file=sys.stderr)
            return 1
    if not checked:
        print("FAIL: no settings.json found in .claude/ or ~/.claude/", file=sys.stderr)
        return 1
    required = {"UserPromptSubmit", "PreToolUse", "PostToolUse", "SessionStart"}
    missing = required - set(hook_sources.keys())
    if missing:
        print(f"FAIL: missing hooks: {missing}", file=sys.stderr)
        return 1
    sources = sorted({hook_sources[h] for h in required})
    print(f"OK: all required hooks present (configured in: {', '.join(sources)})")
    return 0


def main() -> None:
    from importlib.metadata import version as _pkg_version

    try:
        _version_str = _pkg_version("spektralia")
    except Exception:
        _version_str = "0.0.0+unknown"

    parser = argparse.ArgumentParser(prog="spektralia")
    parser.add_argument("--version", action="version", version=f"spektralia {_version_str}")
    parser.add_argument("--api-version", action="version", version=str(_API_VERSION))

    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--explain", action="store_true")

    sub.add_parser("check-ollama")
    sub.add_parser("check-sandbox")
    sub.add_parser("verify-integrity")
    sub.add_parser("verify-installed")
    sub.add_parser("self-test")
    sub.add_parser("stats")
    sub.add_parser("freeze")
    sub.add_parser("unfreeze")

    p_audit_verify = sub.add_parser("audit-verify")
    p_audit_verify.add_argument("path")

    p_rotate = sub.add_parser("audit-rotate")
    p_rotate.add_argument("--keep-days", type=int, default=90)

    p_purge = sub.add_parser("audit-purge")
    p_purge.add_argument("--before", required=True)

    sub.add_parser("scan-config")
    sub.add_parser("hook-check")

    args = parser.parse_args()

    commands = {
        "scan": cmd_scan,
        "check-ollama": cmd_check_ollama,
        "check-sandbox": cmd_check_sandbox,
        "verify-integrity": cmd_verify_integrity,
        "verify-installed": cmd_verify_installed,
        "self-test": cmd_self_test,
        "stats": cmd_stats,
        "freeze": cmd_freeze,
        "unfreeze": cmd_unfreeze,
        "audit-verify": cmd_audit_verify,
        "audit-rotate": cmd_audit_rotate,
        "audit-purge": cmd_audit_purge,
        "scan-config": cmd_scan_config,
        "hook-check": cmd_hook_check,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))
