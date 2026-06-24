"""Tests for Claude Code hook handlers.

Each hook exposes handle(payload: dict) -> dict; tests call that directly.
End-to-end subprocess tests cover the I/O wiring.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

HOOKS_DIR = Path(__file__).parent.parent / "integrations" / "claude_code_hooks"


def load_hook(name: str):
    spec = importlib.util.spec_from_file_location(name, HOOKS_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# UserPromptSubmit
# ---------------------------------------------------------------------------

class TestUserPromptSubmit:
    def setup_method(self):
        self.mod = load_hook("user_prompt_submit")

    def _gate_pass(self, sanitized="safe text"):
        result = MagicMock()
        result.blocked = False
        result.sanitized_text = sanitized
        result.block_reason = ""
        return result

    def _gate_block(self, reason="Blocked: rule(EMAIL)"):
        result = MagicMock()
        result.blocked = True
        result.sanitized_text = ""
        result.block_reason = reason
        return result

    def test_clean_prompt_passes(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_pass("safe text")):
            result = self.mod.handle({"prompt": "hello world"})
        assert result["action"] == "continue"
        assert result["prompt"] == "safe text"

    def test_sensitive_prompt_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_block()):
            result = self.mod.handle({"prompt": "my email is alice@example.com"})
        assert result["action"] == "block"
        assert "block_reason" in result or "reason" in result

    def test_attachment_blocks_immediately(self):
        result = self.mod.handle({
            "prompt": "look at this",
            "attachments": [{"type": "image"}],
        })
        assert result["action"] == "block"
        assert "attachment" in result["reason"].lower()

    def test_exception_in_gate_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", side_effect=RuntimeError("boom")):
            result = self.mod.handle({"prompt": "hello"})
        assert result["action"] == "block"
        assert "hook_error" in result["reason"]

    def test_sensitive_data_error_blocks(self):
        from spektralia.errors import SensitiveDataError
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", side_effect=SensitiveDataError(reason="rule(EMAIL)")):
            result = self.mod.handle({"prompt": "alice@example.com"})
        assert result["action"] == "block"


# ---------------------------------------------------------------------------
# PreToolUse
# ---------------------------------------------------------------------------

class TestPreToolUse:
    def setup_method(self):
        self.mod = load_hook("pre_tool_use")

    def _gate_pass(self):
        result = MagicMock()
        result.blocked = False
        result.sanitized_text = "..."
        result.block_reason = ""
        return result

    def _gate_block(self, reason="Blocked: rule(EMAIL)"):
        result = MagicMock()
        result.blocked = True
        result.block_reason = reason
        return result

    def test_mcp_tool_blocked_by_default_deny(self):
        result = self.mod.handle({
            "tool_name": "mcp__filesystem__read_file",
            "tool_input": {"path": "/tmp/safe"},
        })
        assert result["action"] == "block"
        assert "default-deny" in result["reason"]

    def test_another_mcp_tool_blocked(self):
        # Any mcp__ tool is blocked regardless of content
        result = self.mod.handle({
            "tool_name": "mcp__my_server__my_tool",
            "tool_input": {},
        })
        assert result["action"] == "block"

    def test_task_with_secret_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_block("Blocked: rule(EMAIL)")):
            result = self.mod.handle({
                "tool_name": "Task",
                "tool_input": {"prompt": "email is alice@example.com"},
            })
        assert result["action"] == "block"

    def test_task_with_token_reference_blocks(self):
        # Cross-turn token reference should block even without scanning
        result = self.mod.handle({
            "tool_name": "Task",
            "tool_input": {"prompt": "use [REDACTED:EMAIL:a1b2c3] for auth"},
        })
        assert result["action"] == "block"
        assert "token reference" in result["reason"].lower()

    def test_task_clean_passes(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_pass()):
            result = self.mod.handle({
                "tool_name": "Task",
                "tool_input": {"prompt": "print hello world"},
            })
        assert result["action"] == "continue"

    def test_bash_with_secret_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_block("Blocked: rule(API_KEY_GENERIC)")):
            result = self.mod.handle({
                "tool_name": "Bash",
                "tool_input": {"command": "curl -H 'Authorization: Bearer sk_live_abc123' api.example.com"},
            })
        assert result["action"] == "block"

    def test_non_strict_tool_continues(self):
        # Read/Grep/Glob are not in strict scan set — pass through
        result = self.mod.handle({
            "tool_name": "Read",
            "tool_input": {"file_path": "/etc/hosts"},
        })
        assert result["action"] == "continue"

    def test_exception_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", side_effect=RuntimeError("boom")):
            result = self.mod.handle({
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
            })
        assert result["action"] == "block"


# ---------------------------------------------------------------------------
# PostToolUse
# ---------------------------------------------------------------------------

class TestPostToolUse:
    def setup_method(self):
        self.mod = load_hook("post_tool_use")

    def _gate_pass(self, sanitized="clean output"):
        result = MagicMock()
        result.blocked = False
        result.sanitized_text = sanitized
        result.block_reason = ""
        return result

    def _gate_block(self, reason="Blocked: rule(EMAIL)"):
        result = MagicMock()
        result.blocked = True
        result.block_reason = reason
        return result

    def test_clean_output_substituted(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_pass("clean output")):
            result = self.mod.handle({"output": "some file contents"})
        assert result["action"] == "continue"
        assert result["output"] == "clean output"

    def test_sensitive_output_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_block("Blocked: rule(CREDIT_CARD)")):
            result = self.mod.handle({"output": "card: 4111111111111111"})
        assert result["action"] == "block"

    def test_dict_output_serialized(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", return_value=self._gate_pass("{}")):
            result = self.mod.handle({"output": {"key": "value"}})
        assert result["action"] == "continue"

    def test_exception_blocks(self):
        with patch("spektralia.gate", new=MagicMock()), \
             patch("asyncio.run", side_effect=Exception("unexpected")):
            result = self.mod.handle({"output": "text"})
        assert result["action"] == "block"


# ---------------------------------------------------------------------------
# SessionStart
# ---------------------------------------------------------------------------

class TestSessionStart:
    def setup_method(self):
        self.mod = load_hook("session_start")

    def test_all_checks_pass(self):
        with patch.object(self.mod, "_run_check", return_value=(True, "OK")):
            result = self.mod.handle({})
        assert result["action"] == "continue"

    def test_canary_failure_blocks_session(self):
        def fake_check(cmd):
            if "self-test" in cmd:
                return False, "FAIL: canary payload returned wrong category"
            return True, "OK"

        with patch.object(self.mod, "_run_check", side_effect=fake_check):
            result = self.mod.handle({})
        assert result["action"] == "block"
        assert "self-test" in result["reason"]

    def test_integrity_failure_blocks_session(self):
        def fake_check(cmd):
            if "verify-integrity" in cmd:
                return False, "FAIL: pattern_hash mismatch"
            return True, "OK"

        with patch.object(self.mod, "_run_check", side_effect=fake_check):
            result = self.mod.handle({})
        assert result["action"] == "block"
        assert "verify-integrity" in result["reason"]

    def test_multiple_failures_all_reported(self):
        with patch.object(self.mod, "_run_check", return_value=(False, "failed")):
            result = self.mod.handle({})
        assert result["action"] == "block"
        # All four check names should appear in the reason
        for name in ("verify-integrity", "self-test", "hook-check", "verify-installed"):
            assert name in result["reason"]


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

class TestStop:
    def setup_method(self):
        self.mod = load_hook("stop")

    def test_always_continues(self):
        with patch("spektralia.config.Settings.from_env") as mock_settings, \
             patch("spektralia.audit.AuditChain") as mock_chain:
            mock_chain.return_value.emit = MagicMock()
            mock_chain.return_value.close = MagicMock()
            result = self.mod.handle({})
        assert result["action"] == "continue"

    def test_audit_failure_does_not_block(self):
        # Even if the audit chain blows up, Stop must not block
        with patch("spektralia.config.Settings.from_env", side_effect=Exception("boom")):
            result = self.mod.handle({})
        assert result["action"] == "continue"


# ---------------------------------------------------------------------------
# I/O wiring tests (subprocess)
# ---------------------------------------------------------------------------

class TestHookIoWiring:
    """Verify each hook reads JSON from stdin and writes JSON to stdout."""

    def _run_hook(self, name: str, payload: dict) -> dict:
        script = str(HOOKS_DIR / f"{name}.py")
        proc = subprocess.run(
            [sys.executable, script],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return json.loads(proc.stdout)

    def test_user_prompt_submit_io(self):
        # Attachment payload — blocks without needing Ollama
        result = self._run_hook(
            "user_prompt_submit",
            {"prompt": "hello", "attachments": [{"type": "image"}]},
        )
        assert result["action"] == "block"

    def test_pre_tool_use_mcp_io(self):
        result = self._run_hook(
            "pre_tool_use",
            {"tool_name": "mcp__github__create_issue", "tool_input": {}},
        )
        assert result["action"] == "block"

    def test_pre_tool_use_token_ref_io(self):
        result = self._run_hook(
            "pre_tool_use",
            {
                "tool_name": "Task",
                "tool_input": {"prompt": "use [REDACTED:EMAIL:deadbe] for auth"},
            },
        )
        assert result["action"] == "block"

    def test_invalid_json_blocks(self):
        script = str(HOOKS_DIR / "user_prompt_submit.py")
        proc = subprocess.run(
            [sys.executable, script],
            input="not json",
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout)
        assert result["action"] == "block"
