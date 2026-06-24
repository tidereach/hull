from __future__ import annotations

import unicodedata
from dataclasses import dataclass


# Zero-width and invisible characters
_ZERO_WIDTH = frozenset(
    "​‌‍⁠﻿᠎"  # ZWS, ZWNJ, ZWJ, WJ, BOM, MVS
    "­"  # soft hyphen
)

# Bidi override characters
_BIDI = frozenset(
    "‪‫‬‭‮"  # LRE, RLE, PDF, LRO, RLO
    "⁦⁧⁨⁩"        # LRI, RLI, FSI, PDI
    "؜"                           # ALM
)

# Variation selectors U+FE00–FE0F and tag chars U+E0000–E007F
def _is_variation_or_tag(c: str) -> bool:
    cp = ord(c)
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0000 <= cp <= 0xE007F)


# Homoglyph map: Cyrillic / Greek / Armenian / Cherokee → Latin lookalikes
# Only unambiguous single-char mappings
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian
    "Ա": "U", "Տ": "S",
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


@dataclass
class NormalizeResult:
    normalized: str
    original: str
    # List of (original_offset, char, reason) for removed obfuscation chars
    removals: list[tuple[int, str, str]]
    # Offset map: normalized_index -> original_index
    offset_map: list[int]


def normalize(text: str) -> NormalizeResult:
    """Apply NFKC + obfuscation strip + homoglyph fold.

    Maintains offset_map so scanner can report original positions.
    """
    removals: list[tuple[int, str, str]] = []

    # Pass 1: strip obfuscation chars and build offset map
    filtered: list[str] = []
    offset_map: list[int] = []  # filtered_index -> original_index

    for orig_i, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            removals.append((orig_i, ch, "ZERO_WIDTH"))
            continue
        if ch in _BIDI:
            removals.append((orig_i, ch, "BIDI_OVERRIDE"))
            continue
        if _is_variation_or_tag(ch):
            removals.append((orig_i, ch, "VARIATION_OR_TAG"))
            continue
        filtered.append(ch)
        offset_map.append(orig_i)

    stripped = "".join(filtered)

    # Pass 2: NFKC normalization (may change char counts — we approximate offsets)
    nfkc = unicodedata.normalize("NFKC", stripped)

    # Pass 3: homoglyph fold
    folded = nfkc.translate(_HOMOGLYPH_TABLE)

    # Note: NFKC can change string length; we use the pre-NFKC offset_map
    # as a best-effort approximation (sufficient for span reporting).

    return NormalizeResult(
        normalized=folded,
        original=text,
        removals=removals,
        offset_map=offset_map,
    )


def whitespace_collapsed_shadow(text: str) -> tuple[str, list[int]]:
    """Return (shadow, shadow_to_original_map) with whitespace removed."""
    shadow_chars: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if not ch.isspace():
            shadow_chars.append(ch)
            index_map.append(i)
    return "".join(shadow_chars), index_map
