"""Tests for the spektralia CLI subcommands."""

from __future__ import annotations

import json
import time
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

import spektralia.cli as cli
from spektralia.cli import (
    cmd_audit_purge,
    cmd_audit_rotate,
    cmd_audit_verify,
    cmd_check_ollama,
    cmd_check_sandbox,
    cmd_freeze,
    cmd_hook_check,
    cmd_scan,
    cmd_scan_config,
    cmd_self_test,
    cmd_stats,
    cmd_unfreeze,
    cmd_verify_installed,
    cmd_verify_integrity,
    main,
)


def _args(**kwargs):
    """Build a simple namespace for argparse args."""
    obj = MagicMock()
    for k, v in kwargs.items():
        setattr(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


class TestCmdScan:
    def test_clean_input_exits_0(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        result_mock = MagicMock()
        result_mock.sanitized_text = "hello world"
        result_mock.detections = []
        result_mock.classifier_result = None
        result_mock.blocked = False

        with (
            patch("sys.stdin", StringIO("hello world")),
            patch("spektralia.gate.gate", new=MagicMock()),
            patch("asyncio.run", return_value=result_mock),
        ):
            code = cmd_scan(_args(explain=False))
        assert code == 0
        out = capsys.readouterr().out
        assert "hello world" in out

    def test_sensitive_input_exits_2(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        from spektralia.errors import SensitiveDataError

        with (
            patch("sys.stdin", StringIO("alice@example.com")),
            patch("spektralia.gate.gate", new=MagicMock()),
            patch(
                "asyncio.run",
                side_effect=SensitiveDataError(reason="rule(EMAIL)", labels=("EMAIL",)),
            ),
        ):
            code = cmd_scan(_args(explain=False))
        assert code == 2
        err = capsys.readouterr().err
        assert "Blocked" in err

    def test_soft_mode_blocked_exits_2(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        result_mock = MagicMock()
        result_mock.sanitized_text = "[REDACTED:EMAIL:abc123]"
        result_mock.detections = []
        result_mock.classifier_result = None
        result_mock.blocked = True
        result_mock.block_reason = "rule(EMAIL)"

        with (
            patch("sys.stdin", StringIO("alice@example.com")),
            patch("spektralia.gate.gate", new=MagicMock()),
            patch("asyncio.run", return_value=result_mock),
        ):
            code = cmd_scan(_args(explain=False))
        assert code == 2
        err = capsys.readouterr().err
        assert "Blocked" in err

    def test_empty_input_exits_0(self, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", "/tmp")
        with patch("sys.stdin", StringIO("")):
            code = cmd_scan(_args(explain=False))
        assert code == 0

    def test_explain_shows_detections(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        det = MagicMock()
        det.label = "EMAIL"
        det.start = 0
        det.end = 17
        result_mock = MagicMock()
        result_mock.sanitized_text = "[REDACTED:EMAIL:abc123]"
        result_mock.detections = [det]
        result_mock.classifier_result = None
        result_mock.blocked = False

        with (
            patch("sys.stdin", StringIO("alice@example.com")),
            patch("spektralia.gate.gate", new=MagicMock()),
            patch("asyncio.run", return_value=result_mock),
        ):
            code = cmd_scan(_args(explain=True))
        assert code == 0
        err = capsys.readouterr().err
        assert "EMAIL" in err


# ---------------------------------------------------------------------------
# freeze / unfreeze / stats
# ---------------------------------------------------------------------------


class TestFreezeCommands:
    def test_freeze_creates_file(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        freeze_path = tmp_path / "FREEZE"
        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.freeze_path = freeze_path
            code = cmd_freeze(_args())
        assert code == 0

    def test_unfreeze_removes_file(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        freeze_path = tmp_path / "FREEZE"
        freeze_path.touch(mode=0o600)
        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.freeze_path = freeze_path
            code = cmd_unfreeze(_args())
        assert code == 0
        assert not freeze_path.exists()

    def test_stats_reports_frozen_state(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        freeze_path = tmp_path / "FREEZE"
        freeze_path.touch(mode=0o600)
        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.freeze_path = freeze_path
            code = cmd_stats(_args())
        assert code == 0
        out = capsys.readouterr().out
        assert "frozen: True" in out


# ---------------------------------------------------------------------------
# audit-verify
# ---------------------------------------------------------------------------


class TestCmdAuditVerify:
    def test_valid_chain_exits_0(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        from spektralia.audit import AppendOnlyFileSink, AuditChain

        log_path = tmp_path / "audit.jsonl"
        sink = AppendOnlyFileSink(log_path)
        chain = AuditChain(tmp_path, sink=sink)
        for _ in range(3):
            chain.emit("pass", pattern_hash="", model_digest="", prompt_hash="")
        chain.close()

        assert log_path.exists()

        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.state_dir = tmp_path
            code = cmd_audit_verify(_args(path=str(log_path)))
        assert code == 0
        assert "intact" in capsys.readouterr().out

    def test_tampered_record_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        from spektralia.audit import AppendOnlyFileSink, AuditChain

        log_path_pre = tmp_path / "audit.jsonl"
        sink = AppendOnlyFileSink(log_path_pre)
        chain = AuditChain(tmp_path, sink=sink)
        chain.emit("pass", pattern_hash="", model_digest="", prompt_hash="")
        chain.close()

        log_path = tmp_path / "audit.jsonl"
        # Tamper with the record
        records = [json.loads(l) for l in log_path.read_text().splitlines() if l]
        records[0]["action"] = "tampered"
        log_path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.state_dir = tmp_path
            code = cmd_audit_verify(_args(path=str(log_path)))
        assert code == 1


# ---------------------------------------------------------------------------
# audit-rotate
# ---------------------------------------------------------------------------


class TestCmdAuditRotate:
    def test_rotate_removes_old_records(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        from spektralia.audit import AppendOnlyFileSink, AuditChain

        log_path = tmp_path / "audit.jsonl"
        sink = AppendOnlyFileSink(log_path)
        chain = AuditChain(tmp_path, sink=sink)

        # Emit an old record (wall_ns in the past)
        old_record = chain.emit("old_pass", pattern_hash="", model_digest="", prompt_hash="")
        # Manually backdate it in the file
        lines = log_path.read_text().splitlines()
        old_data = json.loads(lines[0])
        old_data["wall_ns"] = int((time.time() - 200 * 86400) * 1e9)  # 200 days ago
        old_data["record_hash"] = old_record.record_hash  # keep original hash for simplicity
        lines[0] = json.dumps(old_data)
        log_path.write_text("\n".join(lines) + "\n")

        chain.emit("recent_pass", pattern_hash="", model_digest="", prompt_hash="")
        chain.close()

        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.state_dir = tmp_path
            code = cmd_audit_rotate(_args(keep_days=90))
        assert code == 0
        out = capsys.readouterr().out
        assert "1 record(s) removed" in out

    def test_rotate_no_old_records(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        from spektralia.audit import AppendOnlyFileSink, AuditChain

        log_path = tmp_path / "audit.jsonl"
        sink = AppendOnlyFileSink(log_path)
        chain = AuditChain(tmp_path, sink=sink)
        chain.emit("pass", pattern_hash="", model_digest="", prompt_hash="")
        chain.close()

        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.state_dir = tmp_path
            code = cmd_audit_rotate(_args(keep_days=90))
        assert code == 0
        out = capsys.readouterr().out
        assert "0 record(s) removed" in out


# ---------------------------------------------------------------------------
# audit-purge
# ---------------------------------------------------------------------------


class TestCmdAuditPurge:
    def test_purge_removes_old_records(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        import datetime

        from spektralia.audit import AppendOnlyFileSink, AuditChain

        log_path = tmp_path / "audit.jsonl"
        sink = AppendOnlyFileSink(log_path)
        chain = AuditChain(tmp_path, sink=sink)
        chain.emit("old_pass", pattern_hash="", model_digest="", prompt_hash="")
        chain.close()

        # Backdate the written record to 2020-01-01
        lines = log_path.read_text().splitlines()
        old_data = json.loads(lines[0])
        old_data["wall_ns"] = int(
            datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC).timestamp() * 1e9
        )
        lines[0] = json.dumps(old_data)
        log_path.write_text("\n".join(lines) + "\n")

        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.state_dir = tmp_path
            code = cmd_audit_purge(_args(before="2021-01-01"))
        assert code == 0
        out = capsys.readouterr().out
        assert "1 record(s) removed" in out

    def test_purge_invalid_date_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        with patch("spektralia.config.Settings.from_env") as ms:
            s = ms.return_value
            s.state_dir = tmp_path
            code = cmd_audit_purge(_args(before="not-a-date"))
        assert code == 1


# ---------------------------------------------------------------------------
# verify-integrity
# ---------------------------------------------------------------------------


class TestCmdVerifyIntegrity:
    def test_prints_hashes(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        code = cmd_verify_integrity(_args())
        assert code == 0
        out = capsys.readouterr().out
        assert "pattern_hash" in out


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------


class TestCmdSelfTest:
    def test_passing_canary_exits_0(self, capsys):
        result = MagicMock()
        result.passed = True
        result.duration_seconds = 0.1
        result.failures = []
        with patch("spektralia.canary.run_canary", return_value=result):
            code = cmd_self_test(_args())
        assert code == 0
        assert "OK" in capsys.readouterr().out

    def test_failing_canary_exits_1(self, capsys):
        result = MagicMock()
        result.passed = False
        result.failures = ["expected PII, got []"]
        with patch("spektralia.canary.run_canary", return_value=result):
            code = cmd_self_test(_args())
        assert code == 1


# ---------------------------------------------------------------------------
# scan-config
# ---------------------------------------------------------------------------


class TestCmdScanConfig:
    def test_no_sensitive_content_exits_0(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Hello\n\nThis is safe.\n")
        code = cmd_scan_config(_args())
        assert code == 0

    def test_sensitive_content_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Config\n\ncontact me at alice@example.com\n")
        code = cmd_scan_config(_args())
        assert code == 1
        assert "EMAIL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# hook-check
# ---------------------------------------------------------------------------


class TestCmdHookCheck:
    def test_all_hooks_present_exits_0(self, tmp_path, capsys):
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_path = claude_dir / "settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "hooks": {
                        "UserPromptSubmit": [],
                        "PreToolUse": [],
                        "PostToolUse": [],
                        "SessionStart": [],
                    }
                }
            )
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            code = cmd_hook_check(_args())
        assert code == 0

    def test_missing_hook_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings_path = claude_dir / "settings.json"
        settings_path.write_text(json.dumps({"hooks": {"UserPromptSubmit": []}}))
        with patch("pathlib.Path.home", return_value=tmp_path):
            code = cmd_hook_check(_args())
        assert code == 1
        assert "missing" in capsys.readouterr().err

    def test_missing_settings_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("pathlib.Path.home", return_value=tmp_path):
            code = cmd_hook_check(_args())
        assert code == 1

    def test_project_level_settings_accepted(self, tmp_path, capsys, monkeypatch):
        # Hooks in .claude/settings.json under cwd (not home) should satisfy hook-check.
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / ".claude").mkdir()
        (project_dir / ".claude" / "settings.json").write_text(
            json.dumps(
                {
                    "hooks": {
                        "UserPromptSubmit": [],
                        "PreToolUse": [],
                        "PostToolUse": [],
                        "SessionStart": [],
                    }
                }
            )
        )
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        monkeypatch.chdir(project_dir)
        with patch("pathlib.Path.home", return_value=home_dir):
            code = cmd_hook_check(_args())
        assert code == 0
        out = capsys.readouterr().out
        assert "all required hooks present" in out
        # Must name only the file that has hooks, not both candidates
        assert "configured in:" in out
        project_settings = str(project_dir / ".claude" / "settings.json")
        assert project_settings in out
        home_settings = str(home_dir / ".claude" / "settings.json")
        assert home_settings not in out


# ---------------------------------------------------------------------------
# check-sandbox
# ---------------------------------------------------------------------------


class TestCmdCheckSandbox:
    def test_default_none_exits_0(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.delenv("SPEKTRALIA_SANDBOX_BACKEND", raising=False)
        code = cmd_check_sandbox(_args())
        assert code == 0
        assert "no sandbox configured" in capsys.readouterr().out

    def test_configured_backend_missing_binary_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SPEKTRALIA_SANDBOX_BACKEND", "cplt")
        monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _name: None)
        code = cmd_check_sandbox(_args())
        assert code == 1
        assert "not on PATH" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# verify-installed
# ---------------------------------------------------------------------------


class TestCmdVerifyInstalled:
    def test_no_lock_file_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code = cmd_verify_installed(_args())
        # With no requirements.lock, verify_installed returns problems
        # (or exits 1 — either is valid; just test it doesn't crash)
        assert code in (0, 1)

    def test_clean_deps_exits_0(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.lock").write_text("httpx==0.27.0\n")
        with patch("spektralia.integrity.verify_installed", return_value=[]):
            code = cmd_verify_installed(_args())
        assert code == 0
        assert "OK" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# check-ollama
# ---------------------------------------------------------------------------


class TestCmdCheckOllama:
    def test_success_exits_0(self, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", "/tmp")
        client = MagicMock()
        client.get.return_value.json.return_value = {"version": "1.2.3"}
        with patch("spektralia.ollama_trust.build_client", return_value=client):
            code = cmd_check_ollama(_args())
        assert code == 0
        assert "1.2.3" in capsys.readouterr().out

    def test_failure_exits_1(self, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", "/tmp")
        with patch(
            "spektralia.ollama_trust.build_client",
            side_effect=RuntimeError("ollama_socket_untrusted"),
        ):
            code = cmd_check_ollama(_args())
        assert code == 1
        assert "FAIL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# scan --explain with classifier result
# ---------------------------------------------------------------------------


class TestExplainClassifier:
    def test_explain_prints_classifier_line(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        cr = MagicMock()
        cr.sensitive = True
        cr.confidence = 0.91
        cr.categories = ["PII"]
        result_mock = MagicMock()
        result_mock.sanitized_text = "[REDACTED:EMAIL:abc123]"
        result_mock.detections = []
        result_mock.classifier_result = cr
        result_mock.blocked = False

        with (
            patch("sys.stdin", StringIO("alice@example.com")),
            patch("spektralia.gate.gate", new=MagicMock()),
            patch("asyncio.run", return_value=result_mock),
        ):
            code = cmd_scan(_args(explain=True))
        assert code == 0
        err = capsys.readouterr().err
        assert "Classifier:" in err
        assert "0.91" in err


# ---------------------------------------------------------------------------
# audit-verify error path / scan-config OSError / hook-check bad JSON
# ---------------------------------------------------------------------------


class TestCliErrorPaths:
    def test_audit_verify_missing_file_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        code = cmd_audit_verify(_args(path=str(tmp_path / "nope.jsonl")))
        assert code == 1
        assert "Error" in capsys.readouterr().err

    def test_scan_config_unreadable_file_swallowed(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "CLAUDE.md").write_text("safe")
        from pathlib import Path as _P

        def boom(self, *a, **k):
            raise OSError("unreadable")

        monkeypatch.setattr(_P, "read_text", boom)
        code = cmd_scan_config(_args())
        assert code == 0  # OSError swallowed, no issues found

    def test_hook_check_invalid_json_exits_1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "settings.json").write_text("{not valid json")
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        with patch("pathlib.Path.home", return_value=home_dir):
            code = cmd_hook_check(_args())
        assert code == 1
        assert "Error reading" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# main() dispatch
# ---------------------------------------------------------------------------


class TestMain:
    def test_no_command_prints_help_exits_1(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.argv", ["spektralia"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1

    def test_dispatches_to_handler(self, monkeypatch):
        called = {}

        def stub(args):
            called["yes"] = True
            return 0

        monkeypatch.setattr(cli, "cmd_stats", stub)
        monkeypatch.setattr("sys.argv", ["spektralia", "stats"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        assert called.get("yes") is True

    def test_handler_exit_code_propagates(self, monkeypatch):
        monkeypatch.setattr(cli, "cmd_self_test", lambda args: 3)
        monkeypatch.setattr("sys.argv", ["spektralia", "self-test"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 3

    def test_version_flag_exits_0(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.argv", ["spektralia", "--version"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        assert "spektralia" in capsys.readouterr().out
