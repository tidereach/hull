"""Tests for HeartbeatEmitter.

heartbeat.py is on the gate() hot path (gate.py:325) but was previously
unexercised. These tests pin the emit-every-N-calls and emit-on-elapsed-seconds
triggers, the no-emit-on-first-tick behaviour, and the heartbeat payload — using
an injected clock and a mock audit chain (no sleeping, no real Ollama).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import spektralia.heartbeat as heartbeat_mod
from spektralia.heartbeat import HeartbeatEmitter


def _emitter(chain, **kwargs):
    return HeartbeatEmitter(
        chain=chain,
        pattern_hash="phash",
        model_digest="mdigest",
        prompt_hash="prompthash",
        **kwargs,
    )


def _anomaly(counters=None):
    a = MagicMock()
    a.counters.return_value = counters if counters is not None else {"block": 1, "pass": 2}
    return a


# ---------------------------------------------------------------------------
# First tick must not emit (warm-up): _last_beat is set at construction.
# ---------------------------------------------------------------------------


def test_first_tick_does_not_emit(monkeypatch):
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: 1000.0)
    chain = MagicMock()
    emitter = _emitter(chain, heartbeat_seconds=300, heartbeat_every_n_calls=100)
    assert emitter.tick(_anomaly()) is False
    chain.emit.assert_not_called()


# ---------------------------------------------------------------------------
# Emit on the Nth call boundary.
# ---------------------------------------------------------------------------


def test_emit_every_n_calls(monkeypatch):
    # Freeze the clock so only the call-count trigger can fire.
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: 1000.0)
    chain = MagicMock()
    emitter = _emitter(chain, heartbeat_seconds=10**9, heartbeat_every_n_calls=3)
    anomaly = _anomaly()

    assert emitter.tick(anomaly) is False  # call 1
    assert emitter.tick(anomaly) is False  # call 2
    assert emitter.tick(anomaly) is True  # call 3 → 3 % 3 == 0
    chain.emit.assert_called_once()
    assert chain.emit.call_args.args[0] == "heartbeat"


# ---------------------------------------------------------------------------
# Emit on elapsed-seconds boundary even before the call count is reached.
# ---------------------------------------------------------------------------


def test_emit_on_elapsed_seconds(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: clock["t"])
    chain = MagicMock()
    # Large call interval so only the elapsed-seconds trigger can fire.
    emitter = _emitter(chain, heartbeat_seconds=300, heartbeat_every_n_calls=10**9)

    clock["t"] = 1299.0  # 299s elapsed → not due
    assert emitter.tick(_anomaly()) is False

    clock["t"] = 1300.0  # 300s elapsed → due
    assert emitter.tick(_anomaly()) is True
    chain.emit.assert_called_once()


def test_last_beat_resets_after_emit(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: clock["t"])
    chain = MagicMock()
    emitter = _emitter(chain, heartbeat_seconds=300, heartbeat_every_n_calls=10**9)

    clock["t"] = 1300.0
    assert emitter.tick(_anomaly()) is True  # emits, resets _last_beat to 1300
    clock["t"] = 1599.0  # only 299s since the reset → not due again
    assert emitter.tick(_anomaly()) is False
    chain.emit.assert_called_once()


# ---------------------------------------------------------------------------
# Payload contents.
# ---------------------------------------------------------------------------


def test_heartbeat_payload_fields(monkeypatch):
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: 1000.0)
    chain = MagicMock()
    emitter = _emitter(chain, heartbeat_seconds=10**9, heartbeat_every_n_calls=1)
    anomaly = _anomaly({"block": 5})
    canary = SimpleNamespace(passed=True)

    assert emitter.tick(anomaly, last_canary=canary, sink_type="file") is True
    kwargs = chain.emit.call_args.kwargs
    assert chain.emit.call_args.args[0] == "heartbeat"
    assert kwargs["pattern_hash"] == "phash"
    assert kwargs["model_digest"] == "mdigest"
    assert kwargs["prompt_hash"] == "prompthash"
    assert kwargs["counter_snapshot"] == {"block": 5}
    assert kwargs["sink_type"] == "file"
    assert kwargs["call_count"] == 1
    assert kwargs["canary_passed"] is True


def test_heartbeat_canary_passed_none_when_no_canary(monkeypatch):
    monkeypatch.setattr(heartbeat_mod.time, "monotonic", lambda: 1000.0)
    chain = MagicMock()
    emitter = _emitter(chain, heartbeat_seconds=10**9, heartbeat_every_n_calls=1)

    assert emitter.tick(_anomaly(), last_canary=None) is True
    assert chain.emit.call_args.kwargs["canary_passed"] is None
