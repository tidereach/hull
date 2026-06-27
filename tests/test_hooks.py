"""Tests for Claude Code hook handlers.

Each hook exposes handle(payload: dict) -> dict; tests call that directly.
End-to-end subprocess tests cover the I/O wiring.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

HOOKS_DIR = Path(__file__).parent.parent / "integrations" / "claude" / "hooks"

# Token pattern for cross-turn leak tests — split to avoid triggering the hook on this file
_TOKEN_REF = "[REDACTED:" + "EMAIL:a1b2c3]"
_TOKEN_REF_IO = "[REDACTED:" + "EMAIL:deadbe]"


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
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", return_value=self._gate_pass("safe text")),
        ):
            result = self.mod.handle({"prompt": "hello world"})
        assert result == {}

    def test_sensitive_prompt_blocks(self):
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", return_value=self._gate_block()),
        ):
            result = self.mod.handle({"prompt": "some sensitive prompt"})
        assert result["decision"] == "block"
        assert "reason" in result

    def test_attachment_blocks_immediately(self):
        result = self.mod.handle(
            {
                "prompt": "look at this",
                "attachments": [{"type": "image"}],
            }
        )
        assert result["decision"] == "block"
        assert "attachment" in result["reason"].lower()

    def test_exception_in_gate_blocks(self):
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", side_effect=RuntimeError("boom")),
        ):
            result = self.mod.handle({"prompt": "hello"})
        assert result["decision"] == "block"
        assert "hook_error" in result["reason"]

    def test_sensitive_data_error_blocks(self):
        from spektralia.errors import SensitiveDataError

        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", side_effect=SensitiveDataError(reason="rule(EMAIL)")),
        ):
            result = self.mod.handle({"prompt": "some prompt"})
        assert result["decision"] == "block"


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

    def _is_deny(self, result: dict) -> bool:
        return result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def _deny_reason(self, result: dict) -> str:
        return result.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")

    def test_mcp_tool_blocked_by_default_deny(self):
        result = self.mod.handle(
            {
                "tool_name": "mcp__filesystem__read_file",
                "tool_input": {"path": "/tmp/safe"},
            }
        )
        assert self._is_deny(result)
        assert "default-deny" in self._deny_reason(result)

    def test_another_mcp_tool_blocked(self):
        result = self.mod.handle(
            {
                "tool_name": "mcp__my_server__my_tool",
                "tool_input": {},
            }
        )
        assert self._is_deny(result)

    def test_subagent_tool_names_in_strict_scan_set(self):
        # Regression guard for SPEC §18 / PLAN.md §308: the subagent-spawn tool MUST
        # be scanned or a parent agent can launder context into a subagent prompt and
        # bypass UserPromptSubmit. SPEC names it "Task"; some Claude Code versions name
        # it "Agent". Scan both so a future "cleanup" can't drop the deployed one.
        assert {"Task", "Agent"} <= self.mod._STRICT_SCAN_TOOLS

    def test_task_with_secret_blocks(self):
        # SPEC §456: PreToolUse(Task) blocks a subagent prompt containing a secret.
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", return_value=self._gate_block("Blocked: rule(EMAIL)")),
        ):
            result = self.mod.handle(
                {
                    "tool_name": "Task",
                    "tool_input": {"prompt": "some sensitive subagent prompt"},
                }
            )
        assert self._is_deny(result)

    def test_task_with_token_reference_blocks(self):
        result = self.mod.handle(
            {
                "tool_name": "Task",
                "tool_input": {"prompt": "use " + _TOKEN_REF + " for auth"},
            }
        )
        assert self._is_deny(result)
        assert "token reference" in self._deny_reason(result).lower()

    def test_task_clean_passes(self):
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", return_value=self._gate_pass()),
        ):
            result = self.mod.handle(
                {
                    "tool_name": "Task",
                    "tool_input": {"prompt": "print hello world"},
                }
            )
        assert result == {}

    def test_bash_with_secret_blocks(self):
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", return_value=self._gate_block("Blocked: rule(API_KEY_GENERIC)")),
        ):
            result = self.mod.handle(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "curl api.example.com"},
                }
            )
        assert self._is_deny(result)

    def test_non_strict_tool_continues(self):
        # Read/Grep/Glob are not in strict scan set — pass through
        result = self.mod.handle(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/etc/hosts"},
            }
        )
        assert result == {}

    def test_exception_blocks(self):
        with (
            patch("spektralia.gate", new=MagicMock()),
            patch("asyncio.run", side_effect=RuntimeError("boom")),
        ):
            result = self.mod.handle(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "ls"},
                }
            )
        assert self._is_deny(result)

    def test_pre_tool_use_own_source_not_scanned(self):
        # Editing a Spektralia source file must not trigger the hook on its own
        # pattern definitions (self-scan false positive, issue #55).
        # Use a token-reference in the content — this would ordinarily block
        # any other path. The own-source exclusion is path-keyed, so the same
        # content on a non-excluded path MUST still block.
        token_ref = "[REDACTED:" + "EMAIL:a1b2c3]"
        own_source_paths = [
            "/home/user/repo/src/spektralia/patterns.py",
            "/home/user/repo/integrations/claude/hooks/pre_tool_use.py",
        ]
        for fp in own_source_paths:
            result = self.mod.handle(
                {
                    "tool_name": "Write",
                    "tool_input": {"file_path": fp, "content": f"x = '{token_ref}'"},
                }
            )
            assert result == {}, f"expected pass for own-source path {fp!r}, got {result!r}"

    def test_pre_tool_use_non_own_source_still_blocks(self):
        # The exclusion must be path-keyed only: the same token-reference content
        # in a non-excluded file must still be caught.
        token_ref = "[REDACTED:" + "EMAIL:a1b2c3]"
        result = self.mod.handle(
            {
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "/home/user/project/main.py",
                    "content": f"x = '{token_ref}'",
                },
            }
        )
        assert self._is_deny(result), f"expected deny for non-own-source path, got {result!r}"

    def test_pre_tool_use_claude_internal_skips_gate(self):
        # Claude-internal dirs bypass the Ollama classifier (issue #99).
        # Gate must not be called; clean content passes through.
        for fp in [
            "/.claude/plans/plan.md",
            "/.claude/memory/notes.md",
            "/.claude/commands/cmd.md",
            "/.claude/skills/skill.md",
        ]:
            with patch("asyncio.run") as mock_run:
                result = self.mod.handle(
                    {"tool_name": "Write", "tool_input": {"file_path": fp, "content": "ok"}}
                )
            assert result == {}, f"expected pass for {fp!r}, got {result!r}"
            mock_run.assert_not_called()

    def test_pre_tool_use_claude_internal_token_ref_blocks(self):
        # Token-reference check runs before the Claude-internal skip, so a
        # cross-turn leak written to a plan file is still caught (issue #99).
        ref = "[REDACTED:" + "EMAIL:a1b2c3]"
        result = self.mod.handle(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "/.claude/plans/p.md", "content": ref},
            }
        )
        assert self._is_deny(result)
        assert "token reference" in self._deny_reason(result).lower()


# ---------------------------------------------------------------------------
# PostToolUse
# ---------------------------------------------------------------------------


class TestPostToolUse:
    def setup_method(self):
        self.mod = load_hook("post_tool_use")

    def _detection(self, label: str):
        d = MagicMock()
        d.label = label
        return d

    def test_clean_output_passes(self):
        with patch("spektralia.scanner.scan", return_value=[]):
            result = self.mod.handle({"output": "some file contents"})
        assert result == {}

    def test_sensitive_output_blocks(self):
        with patch("spektralia.scanner.scan", return_value=[self._detection("CREDIT_CARD")]):
            result = self.mod.handle({"output": "flagged content"})
        assert result["decision"] == "block"
        assert "CREDIT_CARD" in result["reason"]

    def test_dict_output_serialized(self):
        with patch("spektralia.scanner.scan", return_value=[]):
            result = self.mod.handle({"output": {"key": "value"}})
        assert result == {}

    def test_exception_blocks(self):
        with patch("spektralia.scanner.scan", side_effect=Exception("unexpected")):
            result = self.mod.handle({"output": "text"})
        assert result["decision"] == "block"
        assert "hook_error" in result["reason"]


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
        for name in ("verify-integrity", "self-test", "hook-check", "verify-installed"):
            assert name in result["reason"]


class TestSessionStartHookIntegrity:
    """Hook-script tamper detection at SessionStart (#46)."""

    def setup_method(self):
        self.mod = load_hook("session_start")

    def _setup_manifest(self, tmp_path, monkeypatch):
        from spektralia.hook_manifest import HOOK_FILENAMES, write_manifest

        hooks = tmp_path / "hooks"
        hooks.mkdir()
        for name in HOOK_FILENAMES:
            (hooks / name).write_text(f"# {name}\n")
        state = tmp_path / "state"
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(state))
        write_manifest(state / "hook_manifest.json", hooks)
        return hooks

    def test_clean_install_continues(self, tmp_path, monkeypatch):
        self._setup_manifest(tmp_path, monkeypatch)
        decision, _ = self.mod._check_hook_integrity()
        assert decision == "continue"

    def test_off_mode_skips(self, tmp_path, monkeypatch):
        hooks = self._setup_manifest(tmp_path, monkeypatch)
        (hooks / "stop.py").write_text("# tampered\n")
        monkeypatch.setenv("SPEKTRALIA_HOOK_INTEGRITY_MODE", "off")
        decision, _ = self.mod._check_hook_integrity()
        assert decision == "continue"

    def test_warn_mode_audits_but_continues(self, tmp_path, monkeypatch):
        hooks = self._setup_manifest(tmp_path, monkeypatch)
        (hooks / "stop.py").write_text("# tampered\n")
        monkeypatch.setenv("SPEKTRALIA_HOOK_INTEGRITY_MODE", "warn")
        decision, _ = self.mod._check_hook_integrity()
        assert decision == "continue"

    def test_block_mode_blocks_on_tamper(self, tmp_path, monkeypatch):
        hooks = self._setup_manifest(tmp_path, monkeypatch)
        (hooks / "pre_tool_use.py").write_text("# malicious\n")
        monkeypatch.setenv("SPEKTRALIA_HOOK_INTEGRITY_MODE", "block")
        decision, reason = self.mod._check_hook_integrity()
        assert decision == "block"
        assert "pre_tool_use.py" in reason

    def test_handle_blocks_when_integrity_blocks(self, monkeypatch):
        # Isolate from the (separately-tested) identity emit and subprocess checks.
        monkeypatch.setattr(self.mod, "_emit_hook_identity", lambda payload: None)
        monkeypatch.setattr(
            self.mod, "_check_hook_integrity", lambda: ("block", "Hook script tampering detected")
        )
        result = self.mod.handle({})
        assert result["action"] == "block"
        assert "tampering" in result["reason"]


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------


class TestStop:
    def setup_method(self):
        self.mod = load_hook("stop")

    def test_always_continues(self):
        with (
            patch("spektralia.config.Settings.from_env"),
            patch("spektralia.audit.AuditChain") as mock_chain,
        ):
            mock_chain.return_value.emit = MagicMock()
            mock_chain.return_value.close = MagicMock()
            result = self.mod.handle({})
        assert result["action"] == "continue"

    def test_audit_failure_does_not_block(self):
        # Even if the audit chain blows up, Stop must not block
        with patch("spektralia.config.Settings.from_env", side_effect=Exception("boom")):
            result = self.mod.handle({})
        assert result["action"] == "continue"


class TestStopOutputGating:
    """Assistant-turn output gating via the Stop hook (#47)."""

    def setup_method(self):
        self.mod = load_hook("stop")

    def _audit_actions(self, state_dir):
        log = state_dir / "audit.jsonl"
        if not log.exists():
            return []
        return [json.loads(ln)["action"] for ln in log.read_text().splitlines() if ln.strip()]

    def test_disabled_does_not_scan(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        # gate_outputs unset → default False
        result = self.mod.handle({"assistant_text": "reach me at alice@example.com"})
        assert result["action"] == "continue"
        assert "output_flagged" not in self._audit_actions(tmp_path)

    def test_warn_mode_flags_but_continues(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS", "1")
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS_MODE", "warn")
        result = self.mod.handle({"assistant_text": "reach me at alice@example.com"})
        assert result["action"] == "continue"
        assert "output_flagged" in self._audit_actions(tmp_path)

    def test_block_mode_blocks_on_flag(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS", "1")
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS_MODE", "block")
        result = self.mod.handle({"assistant_text": "the AWS key is AKIAIOSFODNN7EXAMPLE"})
        assert result.get("decision") == "block"
        assert "AWS_KEY" in result["reason"]

    def test_clean_output_continues(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS", "1")
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS_MODE", "block")
        result = self.mod.handle({"assistant_text": "the build passed, all green"})
        assert result["action"] == "continue"
        assert "output_flagged" not in self._audit_actions(tmp_path)

    def test_reads_from_transcript(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS", "1")
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS_MODE", "block")
        transcript = tmp_path / "t.jsonl"
        transcript.write_text(
            json.dumps({"role": "user", "content": "hi"})
            + "\n"
            + json.dumps(
                {
                    "type": "assistant",
                    "message": {"content": [{"type": "text", "text": "key AKIAIOSFODNN7EXAMPLE"}]},
                }
            )
            + "\n"
        )
        result = self.mod.handle({"transcript_path": str(transcript)})
        assert result.get("decision") == "block"

    def test_extract_last_assistant_text_string_body(self, tmp_path):
        transcript = tmp_path / "t.jsonl"
        transcript.write_text(
            json.dumps({"role": "assistant", "content": "first"})
            + "\n"
            + json.dumps({"role": "user", "content": "q"})
            + "\n"
            + json.dumps({"role": "assistant", "content": "second"})
            + "\n"
        )
        assert self.mod._extract_last_assistant_text(str(transcript)) == "second"

    def test_extract_handles_missing_file(self):
        assert self.mod._extract_last_assistant_text("/no/such/transcript.jsonl") == ""

    def test_extract_skips_malformed_lines(self, tmp_path):
        transcript = tmp_path / "t.jsonl"
        transcript.write_text(
            "{not json\n" + json.dumps({"role": "assistant", "content": "ok"}) + "\n"
        )
        assert self.mod._extract_last_assistant_text(str(transcript)) == "ok"

    def test_no_text_available_continues(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("SPEKTRALIA_GATE_OUTPUTS", "1")
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
        assert result["decision"] == "block"

    def test_pre_tool_use_mcp_io(self):
        result = self._run_hook(
            "pre_tool_use",
            {"tool_name": "mcp__github__create_issue", "tool_input": {}},
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_pre_tool_use_token_ref_io(self):
        result = self._run_hook(
            "pre_tool_use",
            {
                "tool_name": "Task",
                "tool_input": {"prompt": "use " + _TOKEN_REF_IO + " for auth"},
            },
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_invalid_json_blocks_user_prompt_submit(self):
        script = str(HOOKS_DIR / "user_prompt_submit.py")
        proc = subprocess.run(
            [sys.executable, script],
            input="not json",
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout)
        assert result["decision"] == "block"

    def test_invalid_json_blocks_pre_tool_use(self):
        script = str(HOOKS_DIR / "pre_tool_use.py")
        proc = subprocess.run(
            [sys.executable, script],
            input="not json",
            capture_output=True,
            text=True,
            timeout=10,
        )
        result = json.loads(proc.stdout)
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


# ---------------------------------------------------------------------------
# Import-failure / venv-unavailable fail-closed paths (PLAN.md §306, bug #3)
# ---------------------------------------------------------------------------


class TestHookImportFailureFailsClosed:
    """When the spektralia package can't be imported (e.g. venv missing), every
    content-scanning hook must fail closed (block/deny), never crash through."""

    def test_pre_tool_use_import_error_denies(self):
        mod = load_hook("pre_tool_use")
        with patch.dict(sys.modules, {"spektralia": None}):
            result = mod.handle({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "hook_import_error" in result["hookSpecificOutput"]["permissionDecisionReason"]

    def test_user_prompt_submit_import_error_blocks(self):
        mod = load_hook("user_prompt_submit")
        with patch.dict(sys.modules, {"spektralia": None}):
            result = mod.handle({"prompt": "hello world"})
        assert result["decision"] == "block"
        assert "hook_import_error" in result["reason"]

    def test_post_tool_use_import_error_blocks(self):
        mod = load_hook("post_tool_use")
        with patch.dict(sys.modules, {"spektralia.scanner": None}):
            result = mod.handle({"output": "some tool output"})
        assert result["decision"] == "block"
        assert "hook_import_error" in result["reason"]
        assert "pip install" in result["reason"]


# ---------------------------------------------------------------------------
# Output-shape contracts (PLAN.md §307, bug #4)
# ---------------------------------------------------------------------------


class TestHookOutputContracts:
    """Pin the exact JSON shape each hook emits so a future drift in the
    Claude Code hook protocol surface is caught."""

    def test_pre_tool_use_deny_shape(self):
        mod = load_hook("pre_tool_use")
        result = mod.handle({"tool_name": "mcp__x__y", "tool_input": {}})
        assert set(result.keys()) == {"hookSpecificOutput"}
        hso = result["hookSpecificOutput"]
        assert set(hso.keys()) == {
            "hookEventName",
            "permissionDecision",
            "permissionDecisionReason",
        }
        assert hso["hookEventName"] == "PreToolUse"
        assert hso["permissionDecision"] == "deny"
        assert isinstance(hso["permissionDecisionReason"], str)

    def test_pre_tool_use_allow_shape(self):
        mod = load_hook("pre_tool_use")
        # Non-strict tool → allow is the empty dict (no stdout written)
        result = mod.handle({"tool_name": "Read", "tool_input": {"file_path": "/x"}})
        assert result == {}

    def test_post_tool_use_block_shape(self):
        mod = load_hook("post_tool_use")
        det = MagicMock()
        det.label = "EMAIL"
        with patch("spektralia.scanner.scan", return_value=[det]):
            result = mod.handle({"output": "flagged"})
        assert set(result.keys()) == {"decision", "reason"}
        assert result["decision"] == "block"
        assert isinstance(result["reason"], str)

    def test_user_prompt_submit_block_shape(self):
        mod = load_hook("user_prompt_submit")
        result = mod.handle({"prompt": "x", "attachments": [{"type": "image"}]})
        assert set(result.keys()) == {"decision", "reason"}
        assert result["decision"] == "block"
        assert isinstance(result["reason"], str)

    def test_session_start_continue_shape(self):
        mod = load_hook("session_start")
        with (
            patch.object(mod, "_run_check", return_value=(True, "OK")),
            patch.object(mod, "_emit_hook_identity", return_value=None),
        ):
            result = mod.handle({})
        assert result == {"action": "continue"}

    def test_session_start_block_shape(self):
        mod = load_hook("session_start")
        with (
            patch.object(mod, "_run_check", return_value=(False, "failed")),
            patch.object(mod, "_emit_hook_identity", return_value=None),
        ):
            result = mod.handle({})
        assert set(result.keys()) == {"action", "reason"}
        assert result["action"] == "block"

    def test_stop_continue_shape(self):
        mod = load_hook("stop")
        with patch("spektralia.config.Settings.from_env", side_effect=Exception("x")):
            result = mod.handle({})
        assert result == {"action": "continue"}
