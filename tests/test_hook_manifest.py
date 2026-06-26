"""Tests for hook-script integrity manifest (#46)."""

from __future__ import annotations

from spektralia.config import Settings
from spektralia.hook_manifest import (
    HOOK_FILENAMES,
    compute_hook_digests,
    read_manifest,
    verify_hook_integrity,
    write_manifest,
)


def _make_hooks_dir(root):
    hooks = root / "hooks"
    hooks.mkdir()
    for name in HOOK_FILENAMES:
        (hooks / name).write_text(f"# {name}\nprint('hook')\n")
    return hooks


class TestComputeDigests:
    def test_digests_all_present_hooks(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        digests = compute_hook_digests(hooks)
        assert set(digests) == set(HOOK_FILENAMES)
        for v in digests.values():
            assert len(v) == 64  # sha256 hex

    def test_missing_file_omitted(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        (hooks / "stop.py").unlink()
        digests = compute_hook_digests(hooks)
        assert "stop.py" not in digests
        assert "session_start.py" in digests

    def test_distinct_content_distinct_digest(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        d1 = compute_hook_digests(hooks)
        (hooks / "stop.py").write_text("# tampered\n")
        d2 = compute_hook_digests(hooks)
        assert d1["stop.py"] != d2["stop.py"]
        assert d1["session_start.py"] == d2["session_start.py"]


class TestWriteReadManifest:
    def test_roundtrip(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        manifest_path = tmp_path / "state" / "hook_manifest.json"
        written = write_manifest(manifest_path, hooks)
        assert manifest_path.exists()
        loaded = read_manifest(manifest_path)
        assert loaded == written
        assert loaded["version"] == 1
        assert loaded["hooks_dir"] == str(hooks.resolve())
        assert set(loaded["digests"]) == set(HOOK_FILENAMES)

    def test_manifest_file_mode_is_0600(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        manifest_path = tmp_path / "hook_manifest.json"
        write_manifest(manifest_path, hooks)
        mode = manifest_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_read_missing_returns_none(self, tmp_path):
        assert read_manifest(tmp_path / "nope.json") is None

    def test_read_corrupt_returns_none(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        assert read_manifest(p) is None


class TestVerifyHookIntegrity:
    def test_no_manifest(self, tmp_path):
        status, problems = verify_hook_integrity(tmp_path / "absent.json")
        assert status == "no_manifest"
        assert problems == []

    def test_ok_when_untouched(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        manifest_path = tmp_path / "hook_manifest.json"
        write_manifest(manifest_path, hooks)
        status, problems = verify_hook_integrity(manifest_path)
        assert status == "ok"
        assert problems == []

    def test_mismatch_on_modified_file(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        manifest_path = tmp_path / "hook_manifest.json"
        write_manifest(manifest_path, hooks)
        (hooks / "pre_tool_use.py").write_text("# malicious payload\n")
        status, problems = verify_hook_integrity(manifest_path)
        assert status == "mismatch"
        assert any("pre_tool_use.py" in p and "digest mismatch" in p for p in problems)

    def test_mismatch_on_deleted_file(self, tmp_path):
        hooks = _make_hooks_dir(tmp_path)
        manifest_path = tmp_path / "hook_manifest.json"
        write_manifest(manifest_path, hooks)
        (hooks / "stop.py").unlink()
        status, problems = verify_hook_integrity(manifest_path)
        assert status == "mismatch"
        assert any("stop.py" in p and "missing" in p for p in problems)


class TestSettingsIntegration:
    def test_default_manifest_path_under_state_dir(self, tmp_path):
        s = Settings(state_dir=tmp_path)
        assert s.effective_hook_manifest_path() == tmp_path / "hook_manifest.json"

    def test_explicit_manifest_path_wins(self, tmp_path):
        custom = tmp_path / "custom" / "m.json"
        s = Settings(state_dir=tmp_path, hook_manifest_path=custom)
        assert s.effective_hook_manifest_path() == custom

    def test_hook_integrity_mode_not_in_config_hash(self, tmp_path):
        a = Settings(state_dir=tmp_path, hook_integrity_mode="warn")
        b = Settings(state_dir=tmp_path, hook_integrity_mode="block")
        assert a.config_hash() == b.config_hash()

    def test_env_override_mode(self, monkeypatch):
        monkeypatch.setenv("SPEKTRALIA_HOOK_INTEGRITY_MODE", "block")
        s = Settings.from_env()
        assert s.hook_integrity_mode == "block"

    def test_env_override_manifest_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SPEKTRALIA_HOOK_MANIFEST_PATH", str(tmp_path / "x.json"))
        s = Settings.from_env()
        assert s.effective_hook_manifest_path() == tmp_path / "x.json"
