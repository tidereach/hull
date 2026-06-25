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
    assert det.check_mutation_pattern(cats) is True  # 4th — deny


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


# ---------------------------------------------------------------------------
# Rolling-window pruning and counter filtering
# ---------------------------------------------------------------------------


def test_events_pruned_outside_window():
    # A negative window forces every recorded event to fall outside the window,
    # so _prune pops it immediately and counters report zero.
    det = AnomalyDetector(window_seconds=-1)
    assert det.record("pass") is False  # pruned before any rate check
    assert all(v == 0 for v in det.counters().values())


def test_counters_ignore_unknown_event_names():
    det = AnomalyDetector()
    det.record("session_end")  # not one of the tracked _COUNTERS
    det.record("block")
    counts = det.counters()
    assert counts["block"] == 1
    assert "session_end" not in counts


# ---------------------------------------------------------------------------
# FreezeSwitch anomaly conditions
# ---------------------------------------------------------------------------


def test_freeze_switch_non_regular_file_is_anomalous(tmp_path):
    # A symlink where the freeze file should be is treated as frozen+anomalous.
    freeze_path = tmp_path / "FREEZE"
    freeze_path.symlink_to(tmp_path / "elsewhere")
    frozen, reason = FreezeSwitch(freeze_path).is_frozen()
    assert frozen is True
    assert reason == "freeze_file_anomalous"


def test_freeze_switch_foreign_owner_is_anomalous(tmp_path, monkeypatch):
    import os

    freeze_path = tmp_path / "FREEZE"
    freeze_path.touch(mode=0o600)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    frozen, reason = FreezeSwitch(freeze_path).is_frozen()
    assert frozen is True
    assert reason == "freeze_file_anomalous"


def test_freeze_switch_wrong_mode_is_anomalous(tmp_path):
    import os

    freeze_path = tmp_path / "FREEZE"
    freeze_path.touch()
    os.chmod(freeze_path, 0o644)  # group/world readable
    frozen, reason = FreezeSwitch(freeze_path).is_frozen()
    assert frozen is True
    assert reason == "freeze_file_anomalous"


def test_unfreeze_when_no_file_is_noop(tmp_path):
    # set_frozen(False) on a missing freeze file swallows FileNotFoundError.
    sw = FreezeSwitch(tmp_path / "FREEZE")
    sw.set_frozen(False)  # must not raise
    assert sw.is_frozen()[0] is False
