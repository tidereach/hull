from __future__ import annotations

import base64
import json
import re as _re
from collections.abc import Callable
from dataclasses import dataclass

import regex

_TIMEOUT_MS = 100


@dataclass(frozen=True)
class Pattern:
    label: str
    regex: str
    validator: Callable[[str], bool] | None = None
    priority: int = 50  # lower = higher priority


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mod11_no(value: str) -> bool:
    """Norwegian national ID (fødselsnummer) MOD-11 double checksum."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) != 11:
        return False
    w1 = [3, 7, 6, 1, 8, 9, 4, 5, 2]
    w2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
    k1 = 11 - (sum(d * w for d, w in zip(digits[:9], w1, strict=False)) % 11)
    if k1 == 11:
        k1 = 0
    if k1 == 10 or k1 != digits[9]:
        return False
    k2 = 11 - (sum(d * w for d, w in zip(digits[:10], w2, strict=False)) % 11)
    if k2 == 11:
        k2 = 0
    if k2 == 10 or k2 != digits[10]:
        return False
    return True


def _jwt_header_valid(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        return "alg" in header
    except Exception:
        return False


PATTERNS: list[Pattern] = [
    Pattern(
        label="EMAIL",
        regex=r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        priority=10,
    ),
    Pattern(
        label="IP_ADDR",
        regex=(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)" r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        priority=20,
    ),
    Pattern(
        label="CVE",
        regex=r"\bCVE-\d{4}-\d{4,}\b",
        priority=30,
    ),
    Pattern(
        label="INTERNAL_HOST",
        regex=r"\b[\w\-]+\.(?:local|internal|corp|lan)\b",
        priority=30,
    ),
    Pattern(
        label="CREDIT_CARD",
        regex=r"\b(?:\d[ \-]?){13,16}\b",
        validator=lambda v: _luhn(_re.sub(r"[\s\-]", "", v)),
        priority=10,
    ),
    Pattern(
        label="NO_PID",
        regex=r"\b\d{6}[ \-]?\d{5}\b",
        validator=lambda v: _mod11_no(_re.sub(r"[\s\-]", "", v)),
        priority=10,
    ),
    # Provider-specific key prefixes (high priority, specific)
    Pattern(
        label="AWS_KEY",
        regex=r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        priority=5,
    ),
    Pattern(
        label="GOOGLE_API_KEY",
        regex=r"\bAIza[0-9A-Za-z\-_]{35}\b",
        priority=5,
    ),
    Pattern(
        label="GOOGLE_OAUTH",
        regex=r"\bya29\.[0-9A-Za-z\-_]+\b",
        priority=5,
    ),
    Pattern(
        label="GITHUB_TOKEN",
        regex=r"\bgh[pours]_[A-Za-z0-9]{36,}\b",
        priority=5,
    ),
    Pattern(
        label="SLACK_TOKEN",
        regex=r"\bxox[bpars]-[0-9A-Za-z\-]{10,}\b",
        priority=5,
    ),
    Pattern(
        label="STRIPE_KEY",
        regex=r"\b(?:sk|pk)_live_[0-9A-Za-z]{24,}\b",
        priority=5,
    ),
    Pattern(
        label="JWT",
        regex=r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*\b",
        validator=_jwt_header_valid,
        priority=5,
    ),
    Pattern(
        label="PRIVATE_KEY_BLOCK",
        regex=r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        priority=1,
    ),
    Pattern(
        label="PRIVATE_KEY_BODY",
        regex=r"(?:[A-Za-z0-9+/]{60,76}\n){10,}[A-Za-z0-9+/]*={0,2}",
        priority=2,
    ),
    Pattern(
        label="API_KEY_GENERIC",
        regex=r"\b(?:api[_\-]?key|secret|token|password|passwd|pwd)[_\-\s]*[:=][_\-\s]*['\"]?[A-Za-z0-9\-_\.]{16,64}['\"]?",
        priority=40,
    ),
]

# Sort by priority ascending (lower number = higher priority)
PATTERNS.sort(key=lambda p: p.priority)


def _compile(pat: Pattern) -> regex.Pattern:
    return regex.compile(pat.regex, regex.IGNORECASE | regex.MULTILINE)


_COMPILED: dict[str, regex.Pattern] = {p.label: _compile(p) for p in PATTERNS}


def match_pattern(pat: Pattern, text: str) -> list[tuple[int, int, str]]:
    """Return list of (start, end, matched_text) for pattern in text.

    Returns Detection(label="REGEX_TIMEOUT") sentinel on timeout.
    Raises nothing — always returns a list.
    """
    compiled = _COMPILED.get(pat.label)
    if compiled is None:
        compiled = _compile(pat)
        _COMPILED[pat.label] = compiled

    results = []
    try:
        for m in compiled.finditer(text, timeout=_TIMEOUT_MS / 1000):
            matched = m.group(0)
            if pat.validator is None or pat.validator(matched):
                results.append((m.start(), m.end(), matched))
    except TimeoutError:
        results.append((-1, -1, "REGEX_TIMEOUT"))
    return results
