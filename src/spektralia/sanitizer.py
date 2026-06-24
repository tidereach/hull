from __future__ import annotations

import os
from dataclasses import dataclass, field

from .memory_safety import Secret
from .scanner import Detection


@dataclass
class Sanitized:
    """Result of sanitizing text. Token map is private."""

    text: str
    _token_map: dict[str, Secret] = field(default_factory=dict, repr=False, compare=False)

    def token_labels(self) -> list[str]:
        return list(self._token_map.keys())


def sanitize(text: str, detections: list[Detection]) -> Sanitized:
    """Replace detected spans with [REDACTED:LABEL:rand] tokens.

    Tokens are unique per-request (random 6-hex suffix).
    Originals are stored as Secret objects in the private token map.
    """
    if not detections:
        return Sanitized(text=text)

    # Sort by start position, remove duplicates
    sorted_dets = sorted(set(detections), key=lambda d: d.start)

    token_map: dict[str, Secret] = {}
    used_suffixes: set[str] = set()
    result: list[str] = []
    prev_end = 0

    for det in sorted_dets:
        start, end = det.start, det.end
        if start < prev_end:
            # Overlapping — skip (deduplication should have handled this)
            continue
        if start > len(text) or end > len(text):
            continue

        # Emit text before this detection
        result.append(text[prev_end:start])

        # Generate unique random suffix
        for _ in range(100):
            suffix = os.urandom(3).hex()
            if suffix not in used_suffixes:
                break
        used_suffixes.add(suffix)

        token = f"[REDACTED:{det.label}:{suffix}]"
        original_value = text[start:end]
        token_map[token] = Secret(original_value.encode("utf-8"), label=det.label)

        result.append(token)
        prev_end = end

    result.append(text[prev_end:])

    return Sanitized(text="".join(result), _token_map=token_map)


def _restore(
    text: str,
    sanitized: Sanitized,
    *,
    unsafe_restore_fields: list[str] | None = None,
) -> str:
    """Private restoration API. Single-use; consumed tokens are removed.

    unsafe_restore_fields: list of token labels to restore. Others are left.
    Only for tests and explicit integrators; never called from public API.
    """
    if unsafe_restore_fields is None:
        unsafe_restore_fields = list(sanitized._token_map.keys())

    result = text
    to_restore = {
        token: sec
        for token, sec in list(sanitized._token_map.items())
        if any(token.startswith(f"[REDACTED:{label}:") for label in unsafe_restore_fields)
    }

    for token, secret in list(to_restore.items()):
        result = result.replace(token, secret.as_str(), 1)
        del sanitized._token_map[token]
        secret.wipe()

    return result
