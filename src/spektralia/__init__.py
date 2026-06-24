"""Spektralia — local pre-cloud sensitivity gate."""
from .config import Settings
from .errors import SensitiveDataError
from .gate import GateResult, gate, gate_sync

__all__ = ["gate", "gate_sync", "SensitiveDataError", "GateResult", "Settings"]
