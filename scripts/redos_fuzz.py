#!/usr/bin/env python3
"""ReDoS timeout-guard fuzz script.

For every pattern in spektralia.patterns, generates an adversarial input
designed to trigger catastrophic backtracking, then asserts the call returns
within 500 ms.

Exit codes:
  0 — all patterns completed within 500 ms (guard is working)
  1 — one or more patterns hung beyond 500 ms (guard failed)

REGEX_TIMEOUT in the result means the guard *fired* (this is good, not a
failure).  A hung call means the guard is absent or broken.
"""

from __future__ import annotations

import sys
import time

from spektralia.patterns import PATTERNS, match_pattern

# Adversarial inputs tuned to stress-test different pattern shapes.
# The generic input (repetition + terminator) is sufficient for most patterns;
# the specialised inputs target email/CC anchors that short-circuit on the
# generic input before reaching pathological backtracking depth.
ADVERSARIAL_INPUTS: dict[str, str] = {
    "EMAIL": "a" * 500 + "@" + "b" * 500 + "." + "c" * 500,
    "CREDIT_CARD": "4" + "1" * 500,
}
_GENERIC = "a" * 10_000 + "!"

# Budget: 100 ms timeout + generous overhead for interpreter startup / GIL.
BUDGET_MS = 500


def main() -> int:
    failures: list[str] = []
    rows: list[tuple[str, float, bool]] = []

    for pat in PATTERNS:
        text = ADVERSARIAL_INPUTS.get(pat.label, _GENERIC)

        t0 = time.perf_counter_ns()
        results = match_pattern(pat, text)
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000

        timed_out = any(
            start == -1 and end == -1 and matched == "REGEX_TIMEOUT"
            for (start, end, matched) in results
        )
        rows.append((pat.label, elapsed_ms, timed_out))

        if elapsed_ms > BUDGET_MS:
            failures.append(
                f"  HUNG  {pat.label}: {elapsed_ms:.1f} ms "
                f"(budget {BUDGET_MS} ms — guard failed)"
            )

    # Print summary table.
    print(f"{'PATTERN':<25}  {'ms':>8}  TIMEOUT_FIRED")
    print("-" * 50)
    for label, ms, fired in rows:
        status = "YES (guard OK)" if fired else "no"
        print(f"{label:<25}  {ms:>8.1f}  {status}")

    if failures:
        print("\nFAILURES — timeout guard did not fire within budget:")
        for line in failures:
            print(line)
        return 1

    print(f"\nAll {len(rows)} patterns completed within {BUDGET_MS} ms budget. Guard is working.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
