from spektralia.integrity import compute_pattern_hash, get_integrity_report
from spektralia.patterns import PATTERNS


def test_pattern_hash_is_deterministic():
    h1 = compute_pattern_hash()
    h2 = compute_pattern_hash()
    assert h1 == h2


def test_pattern_hash_is_64_hex():
    h = compute_pattern_hash()
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_integrity_report_returns_all_keys():
    report = get_integrity_report(None, "llama3.2:3b")
    assert "pattern_hash" in report
    assert "prompt_hash" in report
    assert "model_digest" in report


def test_pattern_hash_changes_with_pattern_change(monkeypatch):
    import spektralia.integrity as integrity_mod
    import spektralia.patterns as patterns_mod

    original = compute_pattern_hash()

    # Temporarily add a fake pattern
    from spektralia.patterns import Pattern
    new_patterns = patterns_mod.PATTERNS + [Pattern(label="FAKE_TEST", regex=r"faketest123")]
    monkeypatch.setattr(patterns_mod, "PATTERNS", new_patterns)
    monkeypatch.setattr(integrity_mod, "PATTERNS", new_patterns)

    modified = compute_pattern_hash()
    assert original != modified
