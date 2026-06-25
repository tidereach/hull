from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .anomaly import AnomalyDetector
    from .audit import AuditChain
    from .canary import CanaryResult


class HeartbeatEmitter:
    """Emit periodic audit heartbeat events."""

    def __init__(
        self,
        chain: AuditChain,
        pattern_hash: str,
        model_digest: str,
        prompt_hash: str,
        heartbeat_seconds: int = 300,
        heartbeat_every_n_calls: int = 100,
    ) -> None:
        self._chain = chain
        self._pattern_hash = pattern_hash
        self._model_digest = model_digest
        self._prompt_hash = prompt_hash
        self._heartbeat_seconds = heartbeat_seconds
        self._heartbeat_every_n_calls = heartbeat_every_n_calls
        self._call_count = 0
        self._last_beat = time.monotonic()

    def tick(
        self,
        anomaly: AnomalyDetector,
        last_canary: CanaryResult | None = None,
        sink_type: str = "unknown",
    ) -> bool:
        """Call after each gate() invocation. Emits heartbeat if due.

        Returns True if heartbeat was emitted.
        """
        self._call_count += 1
        now = time.monotonic()
        elapsed = now - self._last_beat

        if (
            self._call_count % self._heartbeat_every_n_calls == 0
            or elapsed >= self._heartbeat_seconds
        ):
            counters = anomaly.counters()
            self._chain.emit(
                "heartbeat",
                pattern_hash=self._pattern_hash,
                model_digest=self._model_digest,
                prompt_hash=self._prompt_hash,
                counter_snapshot=counters,
                sink_type=sink_type,
                call_count=self._call_count,
                canary_passed=last_canary.passed if last_canary else None,
            )
            self._last_beat = now
            return True
        return False
