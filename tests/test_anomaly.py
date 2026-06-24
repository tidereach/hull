import pytest
from spektralia.anomaly import AnomalyDetector, FreezeSwitch


def test_classifier_unavailable_triggers_freeze():
    det = AnomalyDetector(
        window_seconds=300,
        classifier_unavailable_rate_threshold=0.5,
    )
    # 6 events: 4 classifier_unavailable + 2 pass = 67% rate > 50%
    det.record("pass")
    det.record("pass")
    for _ in range(4):
        det.record("classifier_unavailable")
    assert det.should_freeze
    assert "classifier_unavailable" in det.freeze_reason


def test_canary_drift_triggers_immediate_freeze():
    det = AnomalyDetector()
    frozen = det.record("canary_drift")
    assert frozen is True
    assert det.should_freeze


def test_mutation_pattern_denied_on_fourth():
    det = AnomalyDetector()
    cats = frozenset({"PII"})
    assert det.check_mutation_pattern(cats) is False  # 1st
    assert det.check_mutation_pattern(cats) is False  # 2nd
    assert det.check_mutation_pattern(cats) is False  # 3rd
    assert det.check_mutation_pattern(cats) is True   # 4th — deny


def test_counters_returns_all_keys():
    det = AnomalyDetector()
    det.record("block")
    det.record("pass")
    counts = det.counters()
    assert "block" in counts
    assert "pass" in counts
    assert counts["block"] == 1
    assert counts["pass"] == 1


def test_freeze_switch_file(tmp_path):
    freeze_path = tmp_path / "FREEZE"
    sw = FreezeSwitch(freeze_path)
    frozen, _ = sw.is_frozen()
    assert not frozen

    sw.set_frozen(True)
    frozen, reason = sw.is_frozen()
    assert frozen
    assert reason == "gate_frozen"

    sw.set_frozen(False)
    frozen, _ = sw.is_frozen()
    assert not frozen
