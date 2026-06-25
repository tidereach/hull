from spektralia.canary import _CORPUS, run_canary
from spektralia.scanner import scan


def test_canary_passes_with_real_scanner():
    result = run_canary(scan)
    assert result.passed, f"Canary failures: {result.failures}"


def test_canary_detects_broken_scanner():
    # A scanner that returns nothing — canary should fail for must_detect cases
    def broken_scan(text):
        return []

    result = run_canary(broken_scan)
    assert not result.passed
    assert result.failures


def test_canary_corpus_has_positive_and_negative():
    positives = [c for c in _CORPUS if c.must_detect_regex]
    negatives = [c for c in _CORPUS if not c.must_detect_regex]
    assert positives, "No positive canary cases"
    assert negatives, "No negative canary cases"
