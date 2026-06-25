from __future__ import annotations

import base64
import binascii
import gzip
import re

from .scanner import Detection, scan

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RE = re.compile(r"[0-9a-fA-F]{64,}")
_GZIP_MAGIC = b"\x1f\x8b"


def _decode_and_scan(raw: bytes, outer_start: int, outer_end: int, suffix: str) -> list[Detection]:
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return []
    inner = scan(text)
    return [Detection(label=f"{d.label}_{suffix}", start=outer_start, end=outer_end) for d in inner]


def decode_and_rescan(text: str) -> list[Detection]:
    """Find encoded tokens in text and re-scan their decoded content.

    Nested encodings are not chased (documented limit).
    """
    results: list[Detection] = []

    # Base64 candidates (length ≥ 40, valid charset, optional = padding)
    for m in _BASE64_RE.finditer(text):
        candidate = m.group(0)
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded)
            if decoded:
                results.extend(_decode_and_scan(decoded, m.start(), m.end(), "ENCODED"))
        except (binascii.Error, ValueError):
            pass

    # Hex candidates (length ≥ 64, even length)
    for m in _HEX_RE.finditer(text):
        candidate = m.group(0)
        if len(candidate) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(candidate)
            results.extend(_decode_and_scan(decoded, m.start(), m.end(), "ENCODED"))
        except ValueError:
            pass

    # Gzip magic bytes in base64-encoded content (already covered above)
    # Direct gzip-magic bytes in text (rare but possible in binary pastes)
    idx = 0
    while True:
        pos = text.find("\x1f\x8b", idx)
        if pos == -1:
            break
        raw = text[pos:].encode("latin-1", errors="replace")
        try:
            decoded = gzip.decompress(raw)
            results.extend(_decode_and_scan(decoded, pos, len(text), "ENCODED"))
        except Exception:
            pass
        idx = pos + 1

    return results
