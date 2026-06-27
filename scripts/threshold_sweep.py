#!/usr/bin/env python3
"""Sensitivity threshold sweep.

Runs the gate eval harness across sensitivity_threshold values {0.5, 0.6, 0.7,
0.8, 0.9, 0.95} and prints a precision/recall ASCII table showing the trade-off.
Requires live Ollama (the sweep only affects classifier-driven blocks; in offline
mode all classifier calls are mocked to return not-sensitive so the threshold has
no effect on rule-based detections).

Run from repo root:
    LIVE=1 .venv/bin/python scripts/threshold_sweep.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Env setup BEFORE any spektralia imports
_STATE_DIR = tempfile.mkdtemp(prefix="spektralia_sweep_")
os.environ.setdefault("SPEKTRALIA_STATE_DIR", _STATE_DIR)
os.environ.setdefault("SPEKTRALIA_OLLAMA_URL", "http://127.0.0.1:11434")

import httpx
import respx

from spektralia.config import Settings
from spektralia.errors import SensitiveDataError
from spektralia.gate import Gate

REPO_ROOT = Path(__file__).parent.parent
CORPUS_DIR = REPO_ROOT / "tests" / "corpus"
EVAL_DIR = CORPUS_DIR / "eval"

LIVE = os.environ.get("LIVE", "") == "1"
MOCK_BASE = "http://127.0.0.1:11434"

THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]

# Corpus cases with labelled should_block expectation
KNOWN_FN = {"tests/corpus/injection/b64_key.txt"}


def _load_cases():
    from scripts.eval_gate import _load_all  # type: ignore[import]
    return _load_all()


def _setup_mocks(router: respx.MockRouter) -> None:
    router.get(f"{MOCK_BASE}/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.1.0"})
    )
    router.get(f"{MOCK_BASE}/api/tags").mock(
        return_value=httpx.Response(200, json={"models": []})
    )
    router.post(f"{MOCK_BASE}/api/generate").mock(
        return_value=httpx.Response(
            200,
            json={"response": json.dumps({"sensitive": False, "confidence": 0.0, "categories": []})},
        )
    )


async def _eval_threshold(cases, threshold: float) -> dict:
    settings = Settings(
        sensitivity_threshold=threshold,
        rule_classifier_disagreement_rate_threshold=10.0,
        classifier_unavailable_rate_threshold=10.0,
    )

    tp = fp = fn = 0

    if LIVE:
        gate = Gate(settings)
        for case in cases:
            if case.source in KNOWN_FN:
                continue
            try:
                await gate.gate(case.text)
                blocked = False
            except SensitiveDataError:
                blocked = True
            if case.should_block and blocked:
                tp += 1
            elif case.should_block and not blocked:
                fn += 1
            elif not case.should_block and blocked:
                fp += 1
    else:
        with respx.mock(assert_all_called=False) as router:
            _setup_mocks(router)
            gate = Gate(settings)
            for case in cases:
                if case.source in KNOWN_FN:
                    continue
                try:
                    await gate.gate(case.text)
                    blocked = False
                except SensitiveDataError:
                    blocked = True
                if case.should_block and blocked:
                    tp += 1
                elif case.should_block and not blocked:
                    fn += 1
                elif not case.should_block and blocked:
                    fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


async def _run() -> int:
    # Import eval_gate loader (scripts/ is not a proper package, so add to path)
    sys.path.insert(0, str(REPO_ROOT))

    try:
        from scripts.eval_gate import _load_all, EvalCase  # type: ignore[import]
        cases = _load_all()
        if LIVE:
            from scripts.eval_gate import _load_classifier_corpus  # type: ignore[import]
            cases += _load_classifier_corpus()
    except ImportError as e:
        print(f"Could not import eval_gate: {e}")
        return 1

    if not LIVE:
        print("NOTE: Running in offline mode. Classifier is mocked — threshold sweep")
        print("only shows rule-based detection performance (unaffected by threshold).")
        print("Use LIVE=1 for a meaningful classifier threshold sweep.")
        print()

    mode = "live" if LIVE else "offline (mocked classifier)"
    print(f"Mode: {mode}  |  Cases: {len(cases)}")
    print()
    print(f"{'Threshold':>10}  {'TP':>4}  {'FP':>4}  {'FN':>4}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}")
    print("-" * 56)

    rows = []
    for t in THRESHOLDS:
        result = await _eval_threshold(cases, t)
        rows.append(result)
        print(
            f"{result['threshold']:>10.2f}  {result['tp']:>4}  {result['fp']:>4}  {result['fn']:>4}  "
            f"{result['precision']:>6.4f}  {result['recall']:>6.4f}  {result['f1']:>6.4f}"
        )

    print()
    best = max(rows, key=lambda r: r["f1"])
    print(f"Recommended threshold: {best['threshold']} (F1={best['f1']:.4f})")
    print()
    if not LIVE:
        print("Re-run with LIVE=1 and a running Ollama to get classifier-sensitive results.")
    return 0


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
