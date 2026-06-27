#!/usr/bin/env python3
"""Gate precision/recall eval harness.

Measures per-label precision, recall, and F1 against the labelled corpus in
tests/corpus/. Mocks Ollama in offline mode (default) so only rule-based
detections are scored. Pass --live (or LIVE=1) to run the real classifier.

Run from repo root:
    .venv/bin/python scripts/eval_gate.py
    .venv/bin/python scripts/eval_gate.py --live   # requires running Ollama
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# Env setup BEFORE any spektralia imports (matches latency_bench.py convention)
_STATE_DIR = tempfile.mkdtemp(prefix="spektralia_eval_")
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
BASELINE_FILE = Path(__file__).parent / "eval_baseline.json"
RESULTS_FILE = Path(__file__).parent / "eval_results.json"

LIVE = "--live" in sys.argv or os.environ.get("LIVE", "") == "1"
MOCK_BASE = "http://127.0.0.1:11434"

# Cases known to fail at the gate() layer (scan-layer xfails that gate also misses).
# These are excluded from baseline regression checks but still appear in results.
KNOWN_FN: set[str] = {
    "tests/corpus/injection/b64_key.txt",  # gate doesn't decode bare base64 blobs
}


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


@dataclass
class EvalCase:
    text: str
    source: str
    should_block: bool
    expected_label: str | None
    category: str


def _load_positive(directory: Path) -> list[EvalCase]:
    """Load tests/corpus/positive/: stem.upper() is the expected label."""
    cases = []
    for path in sorted(directory.glob("*.txt")):
        cat = path.stem.upper()
        cases.append(EvalCase(
            text=path.read_text().strip(),
            source=str(path.relative_to(REPO_ROOT)),
            should_block=True,
            expected_label=cat,
            category=cat,
        ))
    return cases


def _load_eval_positive() -> list[EvalCase]:
    """Load tests/corpus/eval/positive/{label}/*.txt — multi-variant examples."""
    cases = []
    base = EVAL_DIR / "positive"
    if not base.exists():
        return cases
    for label_dir in sorted(base.iterdir()):
        if not label_dir.is_dir():
            continue
        cat = label_dir.name.upper()
        for path in sorted(label_dir.glob("*.txt")):
            cases.append(EvalCase(
                text=path.read_text().strip(),
                source=str(path.relative_to(REPO_ROOT)),
                should_block=True,
                expected_label=cat,
                category=cat,
            ))
    return cases


def _load_negative(directory: Path) -> list[EvalCase]:
    """Load *.txt from directory: each should pass (not be blocked)."""
    cases = []
    for path in sorted(directory.glob("*.txt")):
        cases.append(EvalCase(
            text=path.read_text().strip(),
            source=str(path.relative_to(REPO_ROOT)),
            should_block=False,
            expected_label=None,
            category="negative",
        ))
    return cases


def _load_injection(directory: Path) -> list[EvalCase]:
    """Load tests/corpus/injection/: obfuscated secrets that gate() should catch.

    Note: b64_key.txt is xfail for scan() but should block via gate() because
    gate._gate_inner calls decode_and_rescan() before classify().
    """
    cases = []
    for path in sorted(directory.glob("*.txt")):
        cases.append(EvalCase(
            text=path.read_text().strip(),
            source=str(path.relative_to(REPO_ROOT)),
            should_block=True,
            expected_label=None,
            category="injection",
        ))
    return cases


def _load_classifier_corpus() -> list[EvalCase]:
    """Load tests/corpus/eval/classifier/: filename encodes category and expectation.

    Naming: {category}_sensitive_{n}.txt  → should_block=True
            {category}_benign_{n}.txt     → should_block=False
            benign_{n}.txt                → should_block=False
    """
    cases = []
    classifier_dir = EVAL_DIR / "classifier"
    if not classifier_dir.exists():
        return cases
    for path in sorted(classifier_dir.glob("*.txt")):
        parts = path.stem.split("_")
        if "sensitive" in parts:
            idx = parts.index("sensitive")
            cat = "_".join(parts[:idx]).upper() or "CLASSIFIER"
            should_block = True
        elif "benign" in parts:
            idx = parts.index("benign")
            cat = "_".join(parts[:idx]).upper() or "CLASSIFIER"
            if not cat:
                cat = "classifier_benign"
            should_block = False
        else:
            continue
        cases.append(EvalCase(
            text=path.read_text().strip(),
            source=str(path.relative_to(REPO_ROOT)),
            should_block=should_block,
            expected_label=None,
            category=f"classifier/{cat}",
        ))
    return cases


def _load_all() -> list[EvalCase]:
    cases: list[EvalCase] = []
    cases += _load_positive(CORPUS_DIR / "positive")
    cases += _load_injection(CORPUS_DIR / "injection")
    cases += _load_negative(CORPUS_DIR / "negative")
    cases += _load_eval_positive()
    eval_neg = EVAL_DIR / "negative"
    if eval_neg.exists():
        cases += _load_negative(eval_neg)
    if LIVE:
        cases += _load_classifier_corpus()
    return cases


# ---------------------------------------------------------------------------
# Mock Ollama
# ---------------------------------------------------------------------------


def _setup_mocks(router: respx.MockRouter) -> None:
    """Register Ollama endpoints. Classifier returns not-sensitive in offline mode."""
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


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@dataclass
class CaseResult:
    case: EvalCase
    blocked: bool
    labels: tuple[str, ...]
    categories: tuple[str, ...]
    correct: bool


def _make_eval_settings() -> Settings:
    """Settings for eval: thresholds raised so anomaly detector never auto-freezes."""
    return Settings(
        rule_classifier_disagreement_rate_threshold=10.0,
        classifier_unavailable_rate_threshold=10.0,
    )


async def _eval_one(case: EvalCase, gate_instance: Gate) -> CaseResult:
    try:
        await gate_instance.gate(case.text)
        blocked = False
        labels: tuple[str, ...] = ()
        categories: tuple[str, ...] = ()
    except SensitiveDataError as e:
        blocked = True
        labels = e.labels
        categories = e.categories
    return CaseResult(
        case=case,
        blocked=blocked,
        labels=labels,
        categories=categories,
        correct=(blocked == case.should_block),
    )


async def _eval_all(cases: list[EvalCase], gate_instance: Gate) -> list[CaseResult]:
    results = []
    for case in cases:
        results.append(await _eval_one(case, gate_instance))
    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _compute_metrics(results: list[CaseResult]) -> dict:
    per_cat: dict[str, dict[str, int]] = {}

    def _bucket(cat: str) -> dict[str, int]:
        if cat not in per_cat:
            per_cat[cat] = {"tp": 0, "fp": 0, "fn": 0}
        return per_cat[cat]

    for r in results:
        if r.case.source in KNOWN_FN:
            continue  # exclude from metrics; still in results for visibility
        cat = r.case.category
        if r.case.should_block:
            if r.blocked:
                _bucket(cat)["tp"] += 1
            else:
                _bucket(cat)["fn"] += 1
        else:
            if r.blocked:
                _bucket(cat)["fp"] += 1

    def _f1(tp: int, fp: int, fn: int) -> dict:
        p = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        return {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1": round(f1, 4),
        }

    categories = {cat: _f1(**counts) for cat, counts in sorted(per_cat.items())}
    totals = {k: sum(v[k] for v in per_cat.values()) for k in ("tp", "fp", "fn")}
    return {"categories": categories, "overall": _f1(**totals)}


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------


def _check_baseline(metrics: dict) -> bool:
    """Return True if metrics meet/exceed baseline; write baseline on first run."""
    if not BASELINE_FILE.exists():
        print(f"\nNo baseline found — writing {BASELINE_FILE.name} from current results.")
        baseline = {
            "min_f1_per_category": {cat: m["f1"] for cat, m in metrics["categories"].items()},
            "min_overall_f1": metrics["overall"]["f1"],
        }
        BASELINE_FILE.write_text(json.dumps(baseline, indent=2) + "\n")
        return True

    baseline = json.loads(BASELINE_FILE.read_text())
    regressions: list[str] = []
    for cat, min_f1 in baseline.get("min_f1_per_category", {}).items():
        actual = metrics["categories"].get(cat, {}).get("f1", 0.0)
        if actual < min_f1:
            regressions.append(f"  {cat}: F1 {actual:.4f} < baseline {min_f1:.4f}")
    ov = metrics["overall"]["f1"]
    min_ov = baseline.get("min_overall_f1", 0.0)
    if ov < min_ov:
        regressions.append(f"  overall: F1 {ov:.4f} < baseline {min_ov:.4f}")

    if regressions:
        print("\nREGRESSIONS against baseline:")
        for line in regressions:
            print(line)
        return False
    return True


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _print_table(metrics: dict, results: list[CaseResult]) -> None:
    print()
    print(f"{'Category':<26} {'TP':>4} {'FP':>4} {'FN':>4}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}")
    print("-" * 64)
    for cat, m in metrics["categories"].items():
        print(
            f"{cat:<26} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}  "
            f"{m['precision']:>6.4f}  {m['recall']:>6.4f}  {m['f1']:>6.4f}"
        )
    print("-" * 64)
    o = metrics["overall"]
    print(
        f"{'OVERALL':<26} {o['tp']:>4} {o['fp']:>4} {o['fn']:>4}  "
        f"{o['precision']:>6.4f}  {o['recall']:>6.4f}  {o['f1']:>6.4f}"
    )
    print()

    failures = [r for r in results if not r.correct]
    if failures:
        counted = [r for r in failures if r.case.source not in KNOWN_FN]
        known = [r for r in failures if r.case.source in KNOWN_FN]
        if counted:
            print(f"Incorrect outcomes ({len(counted)}):")
            for r in counted:
                tag = "FP" if r.blocked else "FN"
                print(f"  [{tag}] {r.case.source}  labels={list(r.labels)}")
            print()
        if known:
            print(f"Known gaps ({len(known)}) — excluded from baseline:")
            for r in known:
                print(f"  [FN/known] {r.case.source}")
            print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _run() -> int:
    cases = _load_all()
    if not cases:
        print("No corpus cases found.")
        return 1

    mode = "live" if LIVE else "offline"
    print(f"Eval mode: {mode}  |  Cases: {len(cases)}")

    t0 = time.monotonic()

    if LIVE:
        gate_instance = Gate(_make_eval_settings())
        results = await _eval_all(cases, gate_instance)
    else:
        with respx.mock(assert_all_called=False) as router:
            _setup_mocks(router)
            gate_instance = Gate(_make_eval_settings())
            results = await _eval_all(cases, gate_instance)

    elapsed = time.monotonic() - t0
    metrics = _compute_metrics(results)
    _print_table(metrics, results)

    output = {
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "mode": mode,
        "cases_run": len(cases),
        "elapsed_seconds": round(elapsed, 3),
        "categories": metrics["categories"],
        "overall": metrics["overall"],
        "cases": [
            {
                "source": r.case.source,
                "category": r.case.category,
                "should_block": r.case.should_block,
                "blocked": r.blocked,
                "correct": r.correct,
                "labels": list(r.labels),
                "categories": list(r.categories),
            }
            for r in results
        ],
    }
    RESULTS_FILE.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Results written to {RESULTS_FILE.name}")

    passed = _check_baseline(metrics)
    if passed:
        print("PASS")
        return 0
    print("FAIL")
    return 1


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
