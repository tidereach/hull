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
    "⁦⁧⁨⁩"  # LRI, RLI, FSI, PDI
    "؜"  # ALM
)


# Variation selectors U+FE00–FE0F and tag chars U+E0000–E007F
def _is_variation_or_tag(c: str) -> bool:
    cp = ord(c)
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0000 <= cp <= 0xE007F)


# Homoglyph map: Cyrillic / Greek / Armenian / Cherokee → Latin lookalikes
# Only unambiguous single-char mappings
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    # Greek
    "α": "a",
    "β": "b",
    "ε": "e",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Armenian
    "Ա": "U",
    "Տ": "S",
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

    Algorithm:
    1. Iterate over original text char by char.
    2. Skip obfuscation chars (zero-width, bidi, variation/tag), recording removals.
    3. For each kept char, apply NFKC to that single char — may expand 1 → N chars.
    4. Append each expanded output char and its source orig_i to result/offset_map.
    5. Apply homoglyph fold on the fully-built string (1-to-1, offset_map stays valid).
    """
    # Fast-path: pure ASCII text cannot contain any zero-width, BIDI, variation,
    # or tag characters (all are non-ASCII), and NFKC is a no-op on ASCII.
    if text.isascii():
        return NormalizeResult(
            normalized=text,
            original=text,
            removals=[],
            offset_map=list(range(len(text))),
        )

    removals: list[tuple[int, str, str]] = []
    result_chars: list[str] = []
    offset_map: list[int] = []  # normalized_index -> original_index

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
        # NFKC-expand the single char; may produce 1 or more output chars
        expanded = unicodedata.normalize("NFKC", ch)
        for out_ch in expanded:
            result_chars.append(out_ch)
            offset_map.append(orig_i)

    # Homoglyph fold is 1-to-1, so offset_map remains valid
    folded = "".join(result_chars).translate(_HOMOGLYPH_TABLE)

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
