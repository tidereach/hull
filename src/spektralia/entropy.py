from __future__ import annotations

import math
import re
import unicodedata

from .scanner import Detection


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_BASE64_IMAGE_RE = re.compile(r"^data:image/", re.IGNORECASE)
_FILE_PATH_RE = re.compile(r"^[/~\\]|^\w:[/\\]")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _is_allowlisted(token: str) -> bool:
    if _UUID_RE.match(token):
        return True
    if _GIT_SHA_RE.match(token):
        return True
    if _BASE64_IMAGE_RE.match(token):
        return True
    if _FILE_PATH_RE.match(token):
        return True
    return False


_TOKEN_SPLIT = re.compile(r"[\s\x00-\x1f\x7f,;:!?\"'()\[\]{}<>|&*#@=+\-/\\]+")


def find_high_entropy(
    text: str,
    min_len: int = 20,
    threshold: float = 4.5,
) -> list[Detection]:
    """Split text on whitespace+punctuation; flag high-entropy tokens."""
    results: list[Detection] = []
    nfkc = unicodedata.normalize("NFKC", text)

    offset = 0
    for token_match in re.finditer(r"\S+", nfkc):
        token = token_match.group(0)
        tok_start = token_match.start()
        tok_end = token_match.end()

        # Strip punctuation for entropy calc but keep original span
        clean = _TOKEN_SPLIT.sub("", token)

        if len(clean) < min_len:
            continue
        if _is_allowlisted(clean):
            continue
        if _shannon_entropy(clean) >= threshold:
            results.append(Detection(
                label="SECRET_HIGH_ENTROPY",
                start=tok_start,
                end=tok_end,
            ))

    return results
