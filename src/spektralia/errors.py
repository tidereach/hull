from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class SensitiveDataError(Exception):
    """Raised when the gate blocks a payload."""

    reason: str
    labels: tuple[str, ...] = field(default_factory=tuple)
    categories: tuple[str, ...] = field(default_factory=tuple)
    confidence: float = 0.0

    def __str__(self) -> str:
        parts = []
        if self.labels:
            parts.append(f"rule({','.join(self.labels)})")
        if self.categories:
            parts.append(f"classifier({self.confidence:.2f}, {list(self.categories)})")
        detail = " + ".join(parts) if parts else self.reason
        return f"Blocked: {detail}"

    def __repr__(self) -> str:
        return (
            f"SensitiveDataError(reason={self.reason!r}, "
            f"labels={self.labels!r}, categories={self.categories!r})"
        )
