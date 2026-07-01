#!/usr/bin/env python3
"""Enforces MAIN.md § 8 Constraint 6 — the historical Spektralia names MUST
NEVER propagate into the new tidereach/* repositories.

Canonical implementation consumed by:
  - .github/workflows/legacy-name-guard.yml (full-tree scan, no args)
  - .pre-commit-hooks.yaml `legacy-name-guard` hook (file-args scan, as
    invoked by pre-commit's own staged-file selection)

Exemptions:
  1. The `migration/` directory (if a layer repo carries one as a historical
     audit trail).
  2. `CHANGELOG.md` (keep-a-changelog historical-narrative blocks).
  3. Any block bracketed by HTML comments:
       <!-- legacy-name-allowed -->
       ... legacy reference ...
       <!-- /legacy-name-allowed -->
"""

import os
import re
import sys
from pathlib import Path

PATTERN = re.compile(r'[Ss]pektralia|SPEKTRALIA_|~/\.spektralia/|src/spektralia/|spektralia-')
OPEN_TAG = '<!-- legacy-name-allowed -->'
CLOSE_TAG = '<!-- /legacy-name-allowed -->'
SKIP_DIRS = {'.git', 'migration', 'node_modules', '.venv', 'venv', '__pycache__'}
SKIP_FILES = {'CHANGELOG.md'}
# Both paths document the banned pattern by necessity (this docstring; the
# workflow's own header comment) and must self-skip.
SELF_PATHS = ('scripts/legacy_name_guard.py', '.github/workflows/legacy-name-guard.yml')


def scan(path):
    rel = str(path)
    if any(rel.endswith(p) for p in SELF_PATHS) or Path(rel).name in SKIP_FILES:
        return []
    if any(part in SKIP_DIRS for part in Path(rel).parts):
        return []
    try:
        text = path.read_text(encoding='utf-8', errors='strict')
    except (OSError, UnicodeError):
        return []  # binary or unreadable; skip

    hits = []
    in_exempt = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if OPEN_TAG in line:
            in_exempt = True
            continue
        if CLOSE_TAG in line:
            in_exempt = False
            continue
        if in_exempt:
            continue
        if PATTERN.search(line):
            hits.append((rel, lineno, line.rstrip()))
    return hits


def walk_all():
    for dirpath, dirnames, filenames in os.walk('.'):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILES:
                continue
            yield Path(dirpath) / name


def main():
    args = sys.argv[1:]
    paths = [Path(a) for a in args] if args else list(walk_all())

    hits = []
    for path in paths:
        hits.extend(scan(path))

    if hits:
        print('::error::Legacy Spektralia names found (MAIN.md § 8 Constraint 6).')
        print('::error::Wrap intentional historical references in <!-- legacy-name-allowed --> ... <!-- /legacy-name-allowed --> blocks,')
        print('::error::or move the content under migration/ or CHANGELOG.md.')
        print('')
        for path, lineno, line in hits:
            print(f'{path}:{lineno}: {line}')
        sys.exit(1)

    print('legacy-name-guard: clean (MAIN.md § 8 Constraint 6 satisfied).')


if __name__ == '__main__':
    main()
