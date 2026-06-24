import pytest
from pathlib import Path


@pytest.fixture
def tmp_state_dir(tmp_path):
    return tmp_path / ".spektralia"


@pytest.fixture
def settings(tmp_state_dir):
    from spektralia.config import Settings
    return Settings(state_dir=tmp_state_dir, freeze_path=tmp_state_dir / "FREEZE")
