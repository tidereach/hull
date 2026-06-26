from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class _Event:
    name: str
    ts: float = field(default_factory=time.monotonic)


class AnomalyDetector:
    """Rolling counters with configurable auto-freeze thresholds."""

    _COUNTERS = (
        "classifier_unavailable",
        "rule_classifier_disagreement",
        "framing_disagreement",
        "block",
        "pass",
        "warn",
        "canary_drift",
    )

    def __init__(
        self,
        window_seconds: int = 300,
        classifier_unavailable_rate_threshold: float = 0.5,
        rule_classifier_disagreement_rate_threshold: float = 0.5,
    ) -> None:
        self._window = window_seconds
        self._thresholds = {
            "classifier_unavailable": classifier_unavailable_rate_threshold,
            "rule_classifier_disagreement": rule_classifier_disagreement_rate_threshold,
        }
        self._events: deque[_Event] = deque()
        self._should_freeze = False
        self._freeze_reason: str = ""

        # Session-level mutation tracker: categories → count
        self._soft_override_categories: dict[frozenset, int] = {}

    def record(self, name: str) -> bool:
        """Record an event. Returns True if this triggers auto-freeze."""
        self._events.append(_Event(name=name))
        self._prune()

        if name == "canary_drift":
            self._should_freeze = True
            self._freeze_reason = "canary_drift"
            logger.critical("anomaly: canary drift detected — auto-freeze")
            return True

        total = len(self._events)
        if total == 0:
            return False

        for counter, threshold in self._thresholds.items():
            count = sum(1 for e in self._events if e.name == counter)
            rate = count / total
            if rate > threshold and count >= 3:
                self._should_freeze = True
                self._freeze_reason = f"{counter}_rate_high ({rate:.2f})"
                logger.critical(
                    "anomaly: %s rate %.2f > %.2f — auto-freeze", counter, rate, threshold
                )
                return True

        return False

    def check_mutation_pattern(self, categories: frozenset) -> bool:
        """Track soft-override attempts per category set.

        Returns True if this attempt should be denied (mutation pattern).
        """
        count = self._soft_override_categories.get(categories, 0) + 1
        self._soft_override_categories[categories] = count
        return count > 3

    def _prune(self) -> None:
        cutoff = time.monotonic() - self._window
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()

    @property
    def should_freeze(self) -> bool:
        return self._should_freeze

    @property
    def freeze_reason(self) -> str:
        return self._freeze_reason

    def counters(self) -> dict[str, int]:
        self._prune()
        result = dict.fromkeys(self._COUNTERS, 0)
        for e in self._events:
            if e.name in result:
                result[e.name] += 1
        return result


class FreezeSwitch:
    """File-based freeze gate. Checked on every gate() call."""

    def __init__(self, freeze_path: Path) -> None:
        self._path = freeze_path

    def is_frozen(self) -> tuple[bool, str]:
        """Returns (frozen, reason)."""
        import os
        import stat as stat_mod

        try:
            st = os.lstat(str(self._path))
        except FileNotFoundError:
            return False, ""

        mode = stat_mod.S_IMODE(st.st_mode)
        is_regular = stat_mod.S_ISREG(st.st_mode)

        if not is_regular:
            # Symlink or device — treat as anomaly and freeze
            logger.warning("freeze: anomalous freeze file (not regular) — treating as frozen")
            return True, "freeze_file_anomalous"

        if st.st_uid != os.getuid():
            return True, "freeze_file_anomalous"

        if mode != 0o600:
            logger.warning("freeze: mode is %o not 0600 — treating as frozen", mode)
            return True, "freeze_file_anomalous"

        return True, "gate_frozen"

    def set_frozen(self, frozen: bool) -> None:
        if frozen:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._path.touch(mode=0o600)
        else:
            try:
                self._path.unlink()
            except FileNotFoundError:
                pass
