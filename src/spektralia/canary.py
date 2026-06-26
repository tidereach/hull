from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CanaryCase:
    text: str
    # Labels expected from scanner (empty = should be safe)
    expected_labels: list[str]
    # If True, classifier MUST flag as sensitive
    must_classify_sensitive: bool = False
    # If True, scanner must detect regardless of classifier
    must_detect_regex: bool = True


# Canonical canary corpus — deterministic, nonce-salted to defeat key-based backdoors
_CORPUS: list[CanaryCase] = [
    CanaryCase(
        text="Contact alice@example.com about billing",
        expected_labels=["EMAIL"],
        must_detect_regex=True,
    ),
    CanaryCase(
        text="Server at 10.0.0.1 is down",
        expected_labels=["IP_ADDR"],
        must_detect_regex=True,
    ),
    CanaryCase(
        text="AKIAIOSFODNN7EXAMPLE is the AWS key",
        expected_labels=["AWS_KEY"],
        must_detect_regex=True,
    ),
    CanaryCase(
        text="sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxx is the Stripe key",
        expected_labels=["STRIPE_KEY"],
        must_detect_regex=True,
    ),
    CanaryCase(
        text="-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 64 + "\n-----END RSA PRIVATE KEY-----",
        expected_labels=["PRIVATE_KEY_BLOCK"],
        must_detect_regex=True,
    ),
    # Known-safe: should NOT trigger
    CanaryCase(
        text="The quick brown fox jumps over the lazy dog",
        expected_labels=[],
        must_detect_regex=False,
        must_classify_sensitive=False,
    ),
    CanaryCase(
        text="UUID: 550e8400-e29b-41d4-a716-446655440000 and sha 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        expected_labels=[],
        must_detect_regex=False,
    ),
]


@dataclass
class CanaryResult:
    passed: bool
    failures: list[str]
    duration_seconds: float


def run_canary(scanner_fn) -> CanaryResult:
    """Run canary corpus against the scanner.

    scanner_fn: callable(text) -> list[Detection]
    """
    t0 = time.monotonic()
    failures: list[str] = []

    for case in _CORPUS:
        # Add a random nonce to defeat key-based backdoors (still triggers regex)
        nonce = os.urandom(4).hex()
        text = f"{case.text} nonce:{nonce}"

        detections = scanner_fn(text)
        found_labels = {d.label for d in detections}

        if case.must_detect_regex:
            for expected in case.expected_labels:
                if expected not in found_labels:
                    failures.append(
                        f"canary: expected label {expected!r} not found in {found_labels!r} "
                        f"for text {case.text[:40]!r}"
                    )
        elif case.expected_labels == []:
            # Should be safe — no detections expected (ignoring obfuscation chars)
            real_labels = {l for l in found_labels if l != "OBFUSCATION_CHAR"}
            if real_labels:
                failures.append(
                    f"canary: unexpected detections {real_labels!r} for safe text {case.text[:40]!r}"
                )

    duration = time.monotonic() - t0
    if failures:
        logger.critical("canary: %d failures — auto-freeze triggered", len(failures))
        for f in failures:
            logger.critical("canary failure: %s", f)

    return CanaryResult(passed=not failures, failures=failures, duration_seconds=duration)
