#!/usr/bin/env python3
"""Pre-commit guard: if pyproject.toml is staged, require requirements.lock and SBOM.json.

Exits non-zero if:
  - pyproject.toml is staged but requirements.lock is not staged, OR
  - pyproject.toml is staged but SBOM.json is not staged.

This catches the common mistake of editing pyproject.toml (adding/removing deps)
without running `make lock && make sbom`. CI's verify-sbom job already catches
drift after the fact; this hook catches it before the push.

Run from repo root:
    python scripts/check_lock_sbom_fresh.py
"""

from __future__ import annotations

import subprocess
import sys


def _staged_files() -> set[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    return set(result.stdout.splitlines())


def main() -> int:
    staged = _staged_files()

    if "pyproject.toml" not in staged:
        return 0

    failures: list[str] = []

    if "requirements.lock" not in staged:
        failures.append(
            "requirements.lock is not staged. Run `make lock` then stage it.\n"
            "  make lock   # uv pip compile --python-version 3.11 --generate-hashes"
        )

    if "SBOM.json" not in staged:
        failures.append(
            "SBOM.json is not staged. Run `make sbom` then stage it.\n"
            "  make sbom   # cyclonedx-py requirements --output-reproducible -o SBOM.json"
        )

    if failures:
        print("Lock/SBOM guard FAILED — pyproject.toml changed without regenerating lockfile/SBOM:")
        for f in failures:
            print(f"  ✗ {f}")
        print()
        print("Run: make lock && make sbom && git add requirements.lock SBOM.json")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
