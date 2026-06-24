#!/usr/bin/env python3
"""Per-hook p95 latency benchmark for Spektralia.

Calls each Claude Code hook's handle() in-process, mocks all Ollama HTTP
calls with respx (no live Ollama needed), and asserts p95 latencies against
the budgets defined in SPEC.md §20.3.

Run from repo root:
    .venv/bin/python scripts/latency_bench.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import json

# --- Env setup before any spektralia imports ---
# Use a throwaway state dir so audit events don't pollute ~/.spektralia
_STATE_DIR = tempfile.mkdtemp(prefix="spektralia_bench_")
os.environ["SPEKTRALIA_FAIL_OPEN"] = "1"
os.environ["SPEKTRALIA_CLASSIFIER_TIMEOUT_SECONDS"] = "1"
os.environ["SPEKTRALIA_STATE_DIR"] = _STATE_DIR
# Force TCP URL so we can intercept it with respx (overrides .spektralia.toml)
os.environ["SPEKTRALIA_OLLAMA_URL"] = "http://127.0.0.1:11434"

# Add hook dir to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "integrations", "claude_code_hooks"))

import httpx
import respx

from user_prompt_submit import handle as ump_handle
from pre_tool_use import handle as ptu_handle
from post_tool_use import handle as ptou_handle

# ---------------------------------------------------------------------------
# Mock Ollama base URL
# ---------------------------------------------------------------------------
MOCK_BASE = "http://127.0.0.1:11434"

# ---------------------------------------------------------------------------
# Benign 10 KB payload (no PII, no credentials, no patterns that trigger detections)
# ---------------------------------------------------------------------------
_LOREM = (
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor "
    "incididunt ut labore et dolore magna aliqua Ut enim ad minim veniam quis nostrud "
    "exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat Duis aute "
    "irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
    "pariatur Excepteur sint occaecat cupidatat non proident sunt in culpa qui officia "
    "deserunt mollit anim id est laborum "
)
_PAYLOAD_TEXT = (_LOREM * (10 * 1024 // len(_LOREM) + 1))[:10 * 1024]

# Claude Code hook payloads
_UMP_PAYLOAD = {"prompt": _PAYLOAD_TEXT}
_PTU_PAYLOAD = {"tool_name": "Bash", "tool_input": {"command": _PAYLOAD_TEXT}}
_PTOU_PAYLOAD = {"output": _PAYLOAD_TEXT}

# ---------------------------------------------------------------------------
# Mock response builders
# ---------------------------------------------------------------------------

def _ollama_classify_response() -> dict:
    """Valid classifier response: not sensitive."""
    return {"response": json.dumps({"sensitive": False, "confidence": 0.05, "categories": []})}


def _setup_respx_mocks(router: respx.MockRouter) -> None:
    """Register all three Ollama endpoints the gate touches."""
    # _pin_tcp pings /api/version on client init
    router.get(f"{MOCK_BASE}/api/version").mock(
        return_value=httpx.Response(200, json={"version": "0.1.0"})
    )
    # fetch_model_digest hits /api/tags
    router.get(f"{MOCK_BASE}/api/tags").mock(
        return_value=httpx.Response(200, json={"models": []})
    )
    # classify() calls /api/generate twice (two framings in strict mode)
    router.post(f"{MOCK_BASE}/api/generate").mock(
        return_value=httpx.Response(200, json=_ollama_classify_response())
    )


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

N = 20
BUDGETS = {
    "UserPromptSubmit": 500.0,
    "PreToolUse":       300.0,
    "PostToolUse":      200.0,
}

HOOKS = [
    ("UserPromptSubmit", ump_handle, _UMP_PAYLOAD),
    ("PreToolUse",       ptu_handle, _PTU_PAYLOAD),
    ("PostToolUse",      ptou_handle, _PTOU_PAYLOAD),
]


def _run_hook_bench(name: str, handle_fn, payload: dict) -> list[float]:
    """Run handle_fn N times under respx mock, return timings in milliseconds."""
    timings: list[float] = []

    for _ in range(N):
        # Reset module-level singletons so each iteration builds a fresh Gate.
        # This ensures respx intercepts the httpx client created each time.
        try:
            import spektralia.gate as _gate_mod
            import spektralia.ollama_trust as _trust_mod
            _gate_mod._default_gate = None
            _trust_mod.reset_pin()
        except Exception:
            pass

        with respx.mock(assert_all_called=False) as router:
            _setup_respx_mocks(router)

            t0 = time.perf_counter_ns()
            result = handle_fn(payload)
            t1 = time.perf_counter_ns()

        elapsed_ms = (t1 - t0) / 1_000_000
        timings.append(elapsed_ms)

        # Sanity-check: hook must not block (benign payload should pass)
        if result.get("decision") == "block":
            reason = result.get("reason", "")
            print(f"  WARNING: {name} returned block on iteration {len(timings)}: {reason}")

    return timings


def p95(timings: list[float]) -> float:
    """p95 per brief: sort and take index int(0.95 * N)."""
    sorted_t = sorted(timings)
    idx = int(0.95 * len(sorted_t))
    # Clamp to last element
    idx = min(idx, len(sorted_t) - 1)
    return sorted_t[idx]


def main() -> int:
    results: list[tuple[str, float, float, bool]] = []

    for name, handle_fn, payload in HOOKS:
        timings = _run_hook_bench(name, handle_fn, payload)
        p = p95(timings)
        budget = BUDGETS[name]
        passed = p <= budget
        results.append((name, p, budget, passed))

    # Print report
    print()
    all_pass = True
    for name, p, budget, passed in results:
        mark = "PASS" if passed else "FAIL"
        print(f"{name:<20} p95: {p:6.1f} ms  {mark} (budget: {budget:.0f} ms)")
        if not passed:
            all_pass = False
    print()

    if all_pass:
        print("All hooks within budget.")
        return 0
    else:
        print("One or more hooks exceeded budget.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
