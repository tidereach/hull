"""Tests for the cplt-sndbx compose-stack sandbox backend."""

from __future__ import annotations

from pathlib import Path

from spektralia.config import Settings
from spektralia.sandbox import _config_hash, _cplt_sndbx_config_paths, check_sandbox


def _settings(**kw) -> Settings:
    return Settings(sandbox_backend="cplt-sndbx", **kw)


def _make_config_files(tmp_path: Path) -> tuple[str, ...]:
    compose = tmp_path / "docker-compose.yml"
    squid = tmp_path / "squid.conf"
    policy = tmp_path / "agent.policy"
    for f in (compose, squid, policy):
        f.write_text(f"# {f.name}\n")
    return (str(compose), str(squid), str(policy))


# ── Offline bypass ────────────────────────────────────────────────────────────


def test_offline_mode_skips_all_checks(monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SANDBOX_OFFLINE", "1")
    ok, msg = check_sandbox(_settings())
    assert ok
    assert "offline" in msg.lower()


def test_offline_mode_true_string(monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SANDBOX_OFFLINE", "true")
    ok, _ = check_sandbox(_settings())
    assert ok


# ── Runtime (podman/docker) detection ────────────────────────────────────────


def test_no_container_runtime_fails(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEKTRALIA_SANDBOX_OFFLINE", raising=False)
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _: None)
    paths = _make_config_files(tmp_path)
    ok, msg = check_sandbox(_settings(sandbox_config_paths=paths))
    assert not ok
    assert "podman" in msg or "docker" in msg


def test_podman_found_is_ok(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEKTRALIA_SANDBOX_OFFLINE", raising=False)
    monkeypatch.setattr(
        "spektralia.sandbox.shutil.which",
        lambda name: "/usr/bin/podman" if name == "podman" else None,
    )
    paths = _make_config_files(tmp_path)
    ok, msg = check_sandbox(_settings(sandbox_config_paths=paths))
    assert ok
    assert "podman" in msg


def test_docker_fallback_when_no_podman(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEKTRALIA_SANDBOX_OFFLINE", raising=False)
    monkeypatch.setattr(
        "spektralia.sandbox.shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    paths = _make_config_files(tmp_path)
    ok, msg = check_sandbox(_settings(sandbox_config_paths=paths))
    assert ok
    assert "docker" in msg


# ── Config file presence ──────────────────────────────────────────────────────


def test_missing_config_files_fails(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEKTRALIA_SANDBOX_OFFLINE", raising=False)
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _: "/usr/bin/podman")
    absent = (str(tmp_path / "nope.yml"),)
    ok, msg = check_sandbox(_settings(sandbox_config_paths=absent))
    assert not ok
    assert "not found" in msg


# ── Config hash pinning ───────────────────────────────────────────────────────


def test_matching_pin_is_ok(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEKTRALIA_SANDBOX_OFFLINE", raising=False)
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _: "/usr/bin/podman")
    paths = _make_config_files(tmp_path)
    pin = _config_hash(paths)
    ok, _ = check_sandbox(_settings(sandbox_config_paths=paths, sandbox_config_hash=pin))
    assert ok


def test_mismatched_pin_fails(monkeypatch, tmp_path):
    monkeypatch.delenv("SPEKTRALIA_SANDBOX_OFFLINE", raising=False)
    monkeypatch.setattr("spektralia.sandbox.shutil.which", lambda _: "/usr/bin/podman")
    paths = _make_config_files(tmp_path)
    ok, msg = check_sandbox(_settings(sandbox_config_paths=paths, sandbox_config_hash="0" * 64))
    assert not ok
    assert "drift" in msg


# ── _cplt_sndbx_config_paths helper ──────────────────────────────────────────


def test_config_paths_point_to_repo_files():
    paths = _cplt_sndbx_config_paths()
    assert len(paths) == 3
    for p in paths:
        assert "infra/sandbox" in p
    # All three exist now that infra/sandbox is committed.
    existing = [p for p in paths if Path(p).exists()]
    assert len(existing) == 3, f"Some cplt-sndbx config files missing: {paths}"
