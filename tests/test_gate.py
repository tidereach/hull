"""Gate security contract tests.

These tests verify the core gate invariants:
- rule_hit blocks regardless of classifier verdict
- classifier_high blocks with no rule hit
- freeze state blocks all calls
- max_input_chars enforced before classifier
- soft-mode mutation pattern detection
- anomaly auto-freeze on repeated classifier unavailable
- GateResult Detection objects do not expose raw values
"""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest
import respx

from spektralia.config import Settings
from spektralia.errors import SensitiveDataError
from spektralia.gate import Gate

MOCK_BASE = "http://127.0.0.1:11434"


def _cr(sensitive: bool, confidence: float, categories: list[str] | None = None) -> dict:
    """Build mock Ollama /api/generate response body."""
    cats = categories if categories is not None else (["PII"] if sensitive else [])
    return {
        "response": json.dumps(
            {"sensitive": sensitive, "confidence": confidence, "categories": cats}
        )
    }


def _gate(tmp_path, **kwargs) -> Gate:
    s = Settings(
        state_dir=tmp_path / "state",
        freeze_path=tmp_path / "freeze",
        ollama_url=MOCK_BASE,
        **kwargs,
    )
    return Gate(settings=s)


def _mock_client() -> httpx.Client:
    return httpx.Client(base_url=MOCK_BASE)


# ---------------------------------------------------------------------------
# Test 1: rule_hit blocks regardless of classifier saying safe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_rule_hit_blocks_when_classifier_says_safe(tmp_path):
    """rule_hit=True must block even if classifier returns not-sensitive."""
    respx.post(f"{MOCK_BASE}/api/generate").mock(
        side_effect=[
            httpx.Response(200, json=_cr(False, 0.05, [])),
            httpx.Response(200, json=_cr(False, 0.02, [])),
        ]
    )
    g = _gate(tmp_path)
    with patch.object(g, "_get_client", return_value=_mock_client()):
        with pytest.raises(SensitiveDataError) as exc_info:
            await g.gate("Contact alice@example.com today")
    assert "EMAIL" in str(exc_info.value) or "rule" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 2: classifier_high blocks with no rule hit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_classifier_high_blocks_without_rule_hit(tmp_path):
    """classifier_high=True must block even with no regex detection."""
    respx.post(f"{MOCK_BASE}/api/generate").mock(
        side_effect=[
            httpx.Response(200, json=_cr(True, 0.95, ["CONFIDENTIAL"])),
            httpx.Response(200, json=_cr(True, 0.90, ["CONFIDENTIAL"])),
        ]
    )
    g = _gate(tmp_path, sensitivity_threshold=0.7)
    with patch.object(g, "_get_client", return_value=_mock_client()):
        with pytest.raises(SensitiveDataError):
            await g.gate("This is a top-level strategic business plan for Q4")


# ---------------------------------------------------------------------------
# Test 3: Freeze state → block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_freeze_blocks_all_calls(tmp_path):
    """Gate in frozen state must block every call without hitting the classifier."""
    g = _gate(tmp_path)
    g.freeze()
    with pytest.raises(SensitiveDataError) as exc_info:
        await g.gate("hello world")
    err = str(exc_info.value).lower()
    assert "frozen" in err or "freeze" in err or "gate_frozen" in err


# ---------------------------------------------------------------------------
# Test 4: max_input_chars → deterministic block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_max_input_chars_blocks(tmp_path):
    """Input exceeding max_input_chars must raise SensitiveDataError without classifier."""
    g = _gate(tmp_path, max_input_chars=10)
    with pytest.raises(SensitiveDataError) as exc_info:
        await g.gate("x" * 11)
    assert "input_too_large" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 5: Soft mode mutation-until-pass detector blocks after N repeated overrides
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_soft_mode_mutation_pattern_blocks(tmp_path):
    """In soft mode, repeated classifier-high-only overrides for the same
    category set must trigger mutation_pattern_detected block."""
    # Text must not trigger any regex pattern
    safe_text = "This strategic document contains our confidential roadmap"

    # Mock enough calls for 4 gate() invocations in soft mode (2 framings each = 8 calls).
    # Set rule_classifier_disagreement_rate_threshold high so the anomaly auto-freeze
    # does not fire before the mutation pattern detector reaches count > 3.
    g = _gate(
        tmp_path,
        mode="soft",
        sensitivity_threshold=0.7,
        rule_classifier_disagreement_rate_threshold=1.0,
    )
    mock_client = _mock_client()

    with respx.mock:
        respx.post(f"{MOCK_BASE}/api/generate").mock(
            return_value=httpx.Response(200, json=_cr(True, 0.85, ["CONFIDENTIAL"]))
        )
        with patch.object(g, "_get_client", return_value=mock_client):
            # First 3 calls: classifier high, no rule hit → soft mode warns (returns GateResult blocked=True)
            # Cache must be cleared between calls so mutation counter increments each time.
            for _ in range(3):
                g._cache.invalidate_all()
                result = await g.gate(safe_text)
                assert (
                    result.blocked is True
                ), "soft mode should warn, not hard-block, before 4th call"
            # 4th call: same categories → mutation pattern → hard block
            g._cache.invalidate_all()
            with pytest.raises(SensitiveDataError) as exc_info:
                await g.gate(safe_text)
    # reason field carries the machine-readable block cause; __str__ formats differently
    err = exc_info.value
    assert (
        "mutation_pattern" in err.reason.lower()
        or "mutation" in err.reason.lower()
        or "mutation_pattern" in str(err).lower()
        or "mutation" in str(err).lower()
    )


# ---------------------------------------------------------------------------
# Test 6: Anomaly auto-freeze after repeated classifier_unavailable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anomaly_auto_freeze_on_classifier_unavailable(tmp_path):
    """When classifier is unavailable too many times, gate should auto-freeze."""
    g = _gate(
        tmp_path,
        fail_open=False,
        anomaly_window_seconds=300,
        classifier_unavailable_rate_threshold=0.5,
    )
    # Make classifier always fail (connection refused)
    with respx.mock:
        respx.post(f"{MOCK_BASE}/api/generate").mock(side_effect=httpx.ConnectError("refused"))
        with patch.object(g, "_get_client", return_value=_mock_client()):
            # Each call should raise SensitiveDataError (fail-closed)
            # After enough failures, should_freeze becomes True
            for _ in range(4):
                try:
                    await g.gate("hello world")
                except SensitiveDataError:
                    pass
    # After enough classifier_unavailable events, anomaly detector should trigger freeze
    assert g._anomaly.should_freeze is True
    # Frozen state must also block the next call
    with pytest.raises(SensitiveDataError):
        await g.gate("hello world")


# ---------------------------------------------------------------------------
# Test 7: Detection dataclass does not expose raw matched text
# ---------------------------------------------------------------------------


def test_detection_has_no_value_attribute():
    """Detection dataclass must not expose raw matched text as a 'value' attribute."""
    from spektralia.scanner import scan

    dets = scan("Contact alice@example.com today")
    assert dets, "expected at least one Detection for email input"
    for det in dets:
        assert hasattr(det, "label"), "Detection must have label"
        assert hasattr(det, "start"), "Detection must have start"
        assert hasattr(det, "end"), "Detection must have end"
        assert not hasattr(
            det, "value"
        ), "Detection must not have a 'value' attribute (raw text must not be stored)"


# ---------------------------------------------------------------------------
# Test 8: REGEX_TIMEOUT sentinel fails closed before the classifier
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regex_timeout_fails_closed(tmp_path):
    """A REGEX_TIMEOUT detection must hard-block before any classifier call."""
    from spektralia.scanner import Detection

    g = _gate(tmp_path)
    with patch("spektralia.gate.scan", return_value=[Detection("REGEX_TIMEOUT", 0, 0)]):
        with pytest.raises(SensitiveDataError) as exc_info:
            await g.gate("anything at all")
    assert "REGEX_TIMEOUT" in exc_info.value.reason


# ---------------------------------------------------------------------------
# Test 9: classifier raising — fail-open passes, fail-closed blocks (gate.py:206-222)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_classifier_exception_fail_closed_blocks(tmp_path):
    """If classify() itself raises and fail_open is off, block with classifier_unavailable."""
    g = _gate(tmp_path, fail_open=False)
    with (
        patch.object(g, "_get_client", return_value=_mock_client()),
        patch("spektralia.gate.classify", side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(SensitiveDataError) as exc_info:
            await g.gate("plain harmless text with no secrets")
    assert "classifier_unavailable" in exc_info.value.reason


@pytest.mark.asyncio
async def test_classifier_exception_fail_open_passes(tmp_path):
    """If classify() raises but fail_open is on, a clean payload passes (cr is None)."""
    g = _gate(tmp_path, fail_open=True)
    with (
        patch.object(g, "_get_client", return_value=_mock_client()),
        patch("spektralia.gate.classify", side_effect=RuntimeError("boom")),
    ):
        result = await g.gate("plain harmless text with no secrets")
    assert result.blocked is False
    assert result.classifier_result is None


# ---------------------------------------------------------------------------
# Test 10: thread-safe lock path + pass branch + heartbeat tick (gate.py:132-138,316-327)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_thread_safe_pass_path(tmp_path):
    """thread_safe=True acquires the lock; a clean classifier-safe payload passes."""
    respx.post(f"{MOCK_BASE}/api/generate").mock(
        side_effect=[
            httpx.Response(200, json=_cr(False, 0.05, [])),
            httpx.Response(200, json=_cr(False, 0.02, [])),
        ]
    )
    g = _gate(tmp_path, thread_safe=True, sensitivity_threshold=0.7)
    assert g._lock is not None
    with patch.object(g, "_get_client", return_value=_mock_client()):
        result = await g.gate("just some plain harmless prose")
    assert result.blocked is False
    assert result.sanitized_text == "just some plain harmless prose"


# ---------------------------------------------------------------------------
# Test 11: cache hit returns the cached block without re-calling the classifier
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_cache_hit_returns_cached_block(tmp_path):
    """A second identical (no-rule, classifier-high) call is served from cache.

    Sanitized text is unchanged for rule-free input, so the cache key is stable
    across calls and the second call must not hit the classifier again."""
    route = respx.post(f"{MOCK_BASE}/api/generate").mock(
        side_effect=[
            httpx.Response(200, json=_cr(True, 0.95, ["CONFIDENTIAL"])),
            httpx.Response(200, json=_cr(True, 0.92, ["CONFIDENTIAL"])),
        ]
    )
    g = _gate(tmp_path, sensitivity_threshold=0.7)
    text = "our internal strategic roadmap for the next fiscal year"
    with patch.object(g, "_get_client", return_value=_mock_client()):
        with pytest.raises(SensitiveDataError):
            await g.gate(text)
        # Second call: cache hit → raises from cache, no further classifier calls.
        with pytest.raises(SensitiveDataError):
            await g.gate(text)
    assert route.call_count == 2, "classifier should only run on the first (uncached) call"


# ---------------------------------------------------------------------------
# Test 12: framing disagreement is recorded as its own audit event (gate.py:236-247)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_framing_disagreement_recorded(tmp_path):
    """When the two framings disagree beyond threshold, an anomaly event is recorded."""
    respx.post(f"{MOCK_BASE}/api/generate").mock(
        side_effect=[
            httpx.Response(200, json=_cr(True, 0.95, ["PII"])),
            httpx.Response(200, json=_cr(False, 0.05, [])),
        ]
    )
    g = _gate(tmp_path, sensitivity_threshold=0.7, framing_disagreement_threshold=0.3)
    with patch.object(g, "_get_client", return_value=_mock_client()):
        with pytest.raises(SensitiveDataError):
            await g.gate("some text that triggers no regex pattern")
    counters = g._anomaly.counters()
    assert counters.get("framing_disagreement", 0) >= 1


# ---------------------------------------------------------------------------
# Test 13: rule/classifier disagreement recorded when rule fires but classifier safe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_rule_classifier_disagreement_recorded(tmp_path):
    """rule_hit with a not-sensitive classifier verdict records a disagreement event."""
    respx.post(f"{MOCK_BASE}/api/generate").mock(
        side_effect=[
            httpx.Response(200, json=_cr(False, 0.05, [])),
            httpx.Response(200, json=_cr(False, 0.02, [])),
        ]
    )
    g = _gate(tmp_path, rule_classifier_disagreement_rate_threshold=1.0)
    with patch.object(g, "_get_client", return_value=_mock_client()):
        with pytest.raises(SensitiveDataError):
            await g.gate("reach me at alice@example.com")
    counters = g._anomaly.counters()
    assert counters.get("rule_classifier_disagreement", 0) >= 1


# ---------------------------------------------------------------------------
# Test 14: gate_sync() refuses to run inside a live event loop (gate.py:362-373)
# ---------------------------------------------------------------------------


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
@pytest.mark.asyncio
async def test_gate_sync_inside_running_loop_raises():
    """gate_sync() must raise RuntimeError when called from within a running loop."""
    from spektralia.gate import gate_sync

    with pytest.raises(RuntimeError):
        gate_sync("hello world")
