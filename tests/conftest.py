from unittest.mock import patch

import pytest


@pytest.fixture
def tmp_state_dir(tmp_path):
    return tmp_path / ".spektralia"


@pytest.fixture
def settings(tmp_state_dir):
    from spektralia.config import Settings

    return Settings(state_dir=tmp_state_dir, freeze_path=tmp_state_dir / "FREEZE")


def _write_log(tmp_path, lines):
    """Write JSONL fixture data to audit.jsonl under tmp_path."""
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")


@pytest.fixture
def mock_settings():
    """Patch Settings.from_env and yield the mock return value for attribute setting."""
    with patch("spektralia.config.Settings.from_env") as ms:
        yield ms.return_value
