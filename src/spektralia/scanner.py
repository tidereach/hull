from __future__ import annotations

import re as _re
from dataclasses import dataclass

from .normalize import NormalizeResult, normalize, whitespace_collapsed_shadow
from .patterns import PATTERNS, match_pattern


@dataclass(frozen=True)
class Detection:
    """A detected sensitive span. Value is never stored here."""

    label: str
    start: int  # offset in original text
    end: int  # offset in original text

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)


def _remap_offset(offset: int, index_map: list[int]) -> int:
    """Map from shadow/normalized offset back to original."""
    if 0 <= offset < len(index_map):
        return index_map[offset]
    if index_map:
        return index_map[-1]
    return offset


_ALWAYS_EMIT = frozenset({"OBFUSCATION_CHAR", "REGEX_TIMEOUT"})


def _dedupe(detections: list[Detection]) -> list[Detection]:
    """Remove overlapping secret detections; longer span wins.

    OBFUSCATION_CHAR and REGEX_TIMEOUT are always emitted — they represent
    audit-visible events, not secret spans, so overlap suppression must not
    silence them.
    """
    if not detections:
        return []

    always = [d for d in detections if d.label in _ALWAYS_EMIT]
    secrets = [d for d in detections if d.label not in _ALWAYS_EMIT]

    secrets = sorted(secrets, key=lambda d: (d.start, -(d.end - d.start)))
    result: list[Detection] = []
    max_end = -1
    for det in secrets:
        if det.start >= max_end:
            result.append(det)
            max_end = det.end
        elif det.end > max_end:
            result[-1] = det
            max_end = det.end

    return always + result


_UNICODE_EMAIL_RE = _re.compile(r"\b[a-zA-Z0-9._%+\-]+@(\S+)")
_EMAIL_PAT = next(p for p in PATTERNS if p.label == "EMAIL")


def _scan_idna_emails(text: str) -> list[Detection]:
    """Detect emails with non-ASCII domains by IDNA-encoding the domain part."""
    detections = []
    for m in _UNICODE_EMAIL_RE.finditer(text):
        domain = m.group(1).rstrip(".,;:!?")
        if domain.isascii():
            continue
        try:
            encoded = ".".join(
                lbl.encode("idna").decode("ascii") for lbl in domain.split(".") if lbl
            )
            if match_pattern(_EMAIL_PAT, f"x@{encoded}"):
                detections.append(
                    Detection(
                        label="EMAIL",
                        start=m.start(),
                        end=m.start() + len(m.group(0).rstrip(".,;:!?")),
                    )
                )
        except (UnicodeError, ValueError):
            pass
    return detections


def scan(text: str) -> list[Detection]:
    """Run all patterns over text (original + normalized + shadow).

    Returns deduplicated list of Detection with offsets in original text.
    """
    if not text:
        return []

    norm_result: NormalizeResult = normalize(text)
    shadow, shadow_map = whitespace_collapsed_shadow(text)

    all_detections: list[Detection] = []

    for pat in PATTERNS:
        # Scan original text
        for start, end, _matched in match_pattern(pat, text):
            if start == -1:
                # REGEX_TIMEOUT — treat as block signal
                all_detections.append(Detection(label="REGEX_TIMEOUT", start=0, end=len(text)))
                continue
            all_detections.append(Detection(label=pat.label, start=start, end=end))

        # Scan normalized form (if different from original)
        if norm_result.normalized != text:
            for start, end, _matched in match_pattern(pat, norm_result.normalized):
                if start == -1:
                    all_detections.append(Detection(label="REGEX_TIMEOUT", start=0, end=len(text)))
                    continue
                # Remap to original offsets
                orig_start = _remap_offset(start, norm_result.offset_map)
                orig_end = _remap_offset(end - 1, norm_result.offset_map) + 1
                all_detections.append(Detection(label=pat.label, start=orig_start, end=orig_end))

        # Scan whitespace-collapsed shadow
        if shadow != text:
            for start, end, _matched in match_pattern(pat, shadow):
                if start == -1:
                    all_detections.append(Detection(label="REGEX_TIMEOUT", start=0, end=len(text)))
                    continue
                orig_start = _remap_offset(start, shadow_map)
                orig_end = _remap_offset(end - 1, shadow_map) + 1
                all_detections.append(Detection(label=pat.label, start=orig_start, end=orig_end))

    # Emit obfuscation char detections
    for orig_i, _ch, _reason in norm_result.removals:
        all_detections.append(Detection(label="OBFUSCATION_CHAR", start=orig_i, end=orig_i + 1))

    # IDN email shadow: detect emails with unicode (non-ASCII) domains
    all_detections.extend(_scan_idna_emails(text))

    return _dedupe(all_detections)
