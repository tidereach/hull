"""Settings loading: precedence, env coercion errors, and TOML section handling.

test_config_hash_covers_all_settings.py covers hashing; this file covers the
kwargs > env > toml > defaults cascade in Settings.from_env / from_toml, the
ValueError raised on un-coercible env values, and the documented gotcha that a
[spektralia] section makes top-level TOML keys be ignored.
"""

from __future__ import annotations

import os

import pytest

from spektralia.config import Settings


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """Isolate cwd, HOME, and SPEKTRALIA_* env so TOML discovery is deterministic."""
    for key in list(os.environ):
        if key.startswith("SPEKTRALIA_"):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_defaults_when_no_toml_or_env(isolated):
    s = Settings.from_env()
    assert s.ollama_model == "llama3.1:8b"
    assert s.mode == "strict"
    assert s.fail_open is False


def test_toml_loaded_under_section(isolated):
    (isolated / ".spektralia.toml").write_text(
        '[spektralia]\nmode = "soft"\nollama_model = "from-toml"\n'
    )
    s = Settings.from_env()
    assert s.mode == "soft"
    assert s.ollama_model == "from-toml"


def test_env_overrides_toml(isolated, monkeypatch):
    (isolated / ".spektralia.toml").write_text('[spektralia]\nollama_model = "from-toml"\n')
    monkeypatch.setenv("SPEKTRALIA_OLLAMA_MODEL", "from-env")
    s = Settings.from_env()
    assert s.ollama_model == "from-env"


def test_kwargs_override_env(isolated, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_OLLAMA_MODEL", "from-env")
    s = Settings.from_env(ollama_model="from-kwargs")
    assert s.ollama_model == "from-kwargs"


def test_invalid_env_int_raises(isolated, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_MAX_INPUT_CHARS", "not-an-int")
    with pytest.raises(ValueError, match="SPEKTRALIA_MAX_INPUT_CHARS"):
        Settings.from_env()


def test_invalid_env_float_raises(isolated, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SENSITIVITY_THRESHOLD", "high")
    with pytest.raises(ValueError, match="SPEKTRALIA_SENSITIVITY_THRESHOLD"):
        Settings.from_env()


def test_bool_env_coercion(isolated, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_FAIL_OPEN", "yes")
    assert Settings.from_env().fail_open is True
    monkeypatch.setenv("SPEKTRALIA_FAIL_OPEN", "0")
    assert Settings.from_env().fail_open is False


def test_section_present_top_level_keys_ignored(isolated):
    """Documented gotcha: with a [spektralia] section, top-level keys are ignored."""
    (isolated / ".spektralia.toml").write_text(
        'ollama_model = "ignored-top-level"\n[spektralia]\nmode = "soft"\n'
    )
    s = Settings.from_env()
    assert s.mode == "soft"
    assert s.ollama_model == "llama3.1:8b"  # top-level key did not apply


def test_no_section_falls_back_to_top_level(isolated):
    """With no [spektralia] section, bare top-level keys are accepted as a fallback."""
    (isolated / ".spektralia.toml").write_text('mode = "soft"\n')
    assert Settings.from_env().mode == "soft"


def test_from_toml_explicit_path_and_path_coercion(isolated):
    toml_path = isolated / "custom.toml"
    state = isolated / "statedir"
    toml_path.write_text(f'[spektralia]\nstate_dir = "{state}"\nmode = "soft"\n')
    s = Settings.from_toml(toml_path)
    assert s.mode == "soft"
    # state_dir must be coerced from str to Path
    from pathlib import Path

    assert isinstance(s.state_dir, Path)
    assert s.state_dir == state


def test_from_toml_overrides(isolated):
    toml_path = isolated / "custom.toml"
    toml_path.write_text('[spektralia]\nmode = "soft"\n')
    s = Settings.from_toml(toml_path, mode="strict")
    assert s.mode == "strict"
