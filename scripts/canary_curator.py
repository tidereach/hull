#!/usr/bin/env python3
"""Canary-corpus curator.

Reads failing cases from scripts/eval_results.json or scripts/redteam_fuzz.py
output (passed on stdin or specified via --from-eval / --from-redteam) and
proposes new CanaryCase entries for src/spektralia/canary/corpus/.

Interactive by default (prompts for confirmation). Pass --yes to accept all
proposals non-interactively.

Run from repo root:
    .venv/bin/python scripts/canary_curator.py --from-eval     # from A1
    .venv/bin/python scripts/canary_curator.py --from-redteam  # from A2
    .venv/bin/python scripts/canary_curator.py --from-eval --yes
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
CORPUS_DIR = REPO_ROOT / "src" / "spektralia" / "canary" / "corpus"
EVAL_RESULTS = REPO_ROOT / "scripts" / "eval_results.json"

AUTO_YES = "--yes" in sys.argv
FROM_EVAL = "--from-eval" in sys.argv
FROM_REDTEAM = "--from-redteam" in sys.argv


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def _propose(text: str, expected_labels: list[str], must_detect_regex: bool, source: str) -> bool:
    """Ask user to confirm, then write a JSON case file. Returns True if written."""
    out_name = f"{_short_hash(text)}_{expected_labels[0] if expected_labels else 'negative'}.json"
    out_path = CORPUS_DIR / out_name

    if out_path.exists():
        print(f"  Already curated: {out_name}")
        return False

    case = {
        "text": text,
        "expected_labels": expected_labels,
        "must_classify_sensitive": False,
        "must_detect_regex": must_detect_regex,
        "_source": source,
    }

    print()
    print(f"  Source:   {source}")
    print(f"  Text:     {text[:80]!r}")
    print(f"  Labels:   {expected_labels}")
    print(f"  MustDetect: {must_detect_regex}")
    print(f"  OutFile:  {out_name}")

    if AUTO_YES:
        answer = "y"
    else:
        answer = input("  Add to canary corpus? [y/N] ").strip().lower()

    if answer == "y":
        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(case, indent=2) + "\n")
        print(f"  Written: {out_path.relative_to(REPO_ROOT)}")
        return True
    return False


def _curate_from_eval() -> int:
    if not EVAL_RESULTS.exists():
        print(f"No eval results found at {EVAL_RESULTS}. Run scripts/eval_gate.py first.")
        return 1

    results = json.loads(EVAL_RESULTS.read_text())
    failing = [c for c in results.get("cases", []) if not c["correct"]]

    if not failing:
        print("No failing cases in eval results.")
        return 0

    print(f"Found {len(failing)} failing case(s) from eval harness:")
    written = 0
    for case in failing:
        if not case["should_block"] and case["blocked"]:
            # False positive — benign text that got blocked. Not a canary candidate.
            print(f"  Skipping FP (benign): {case['source']}")
            continue
        # False negative — should have blocked, didn't
        text = Path(REPO_ROOT / case["source"]).read_text().strip()
        expected_label = case.get("category", "UNKNOWN")
        if written_this := _propose(
            text=text,
            expected_labels=(
                [expected_label] if expected_label not in ("negative", "injection") else []
            ),
            must_detect_regex=True,
            source=f"eval_results.json FN: {case['source']}",
        ):
            written += 1

    print(f"\n{written} new canary case(s) written to {CORPUS_DIR.relative_to(REPO_ROOT)}/")
    return 0


def _curate_from_redteam() -> int:
    print("Paste redteam_fuzz.py output (BYPASSES section), then press Ctrl-D:")
    print(
        "  (or pipe: .venv/bin/python scripts/redteam_fuzz.py | python scripts/canary_curator.py --from-redteam --yes)"
    )
    print()

    lines = sys.stdin.read().splitlines()
    bypass_lines = []
    in_bypasses = False
    for line in lines:
        if "BYPASSES" in line:
            in_bypasses = True
            continue
        if in_bypasses and line.startswith("  ["):
            bypass_lines.append(line.strip())
        elif in_bypasses and line == "":
            break

    if not bypass_lines:
        print("No bypass lines found. Expected lines like:  [LABEL] mutation: 'text...'")
        return 1

    print(f"Found {len(bypass_lines)} bypass line(s):")
    written = 0
    for line in bypass_lines:
        # Format: [LABEL] mutation: 'text...'
        try:
            label_part, rest = line.split("]", 1)
            label = label_part.lstrip("[")
            mutation, snippet = rest.split(":", 1)
            text = snippet.strip().strip("'\"")
        except ValueError:
            print(f"  Could not parse line: {line!r}")
            continue

        if _propose(
            text=text,
            expected_labels=[label],
            must_detect_regex=True,
            source=f"redteam_fuzz.py bypass: {label}/{mutation.strip()}",
        ):
            written += 1

    print(f"\n{written} new canary case(s) written to {CORPUS_DIR.relative_to(REPO_ROOT)}/")
    return 0


def main() -> int:
    if not FROM_EVAL and not FROM_REDTEAM:
        print("Usage: canary_curator.py --from-eval | --from-redteam [--yes]")
        print("  --from-eval     read failing cases from scripts/eval_results.json")
        print("  --from-redteam  read bypass lines from stdin (pipe redteam_fuzz.py output)")
        print("  --yes           accept all proposals non-interactively")
        return 1

    if FROM_EVAL:
        return _curate_from_eval()
    return _curate_from_redteam()


if __name__ == "__main__":
    sys.exit(main())
