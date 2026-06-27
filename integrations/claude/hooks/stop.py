#!/usr/bin/env python3
"""Claude Code Stop hook — emit session_end audit roll-up and gate the output.

When ``Settings.gate_outputs`` is enabled, the finalized assistant turn is read
from the transcript and scanned with the deterministic pipeline (#47). In "warn"
mode a flagged turn emits an audit event and the session still stops; in "block"
mode the Stop is refused so the model is asked to revise its output.
"""

from __future__ import annotations

import json
import sys


def _extract_last_assistant_text(transcript_path: str) -> str:
    """Best-effort extraction of the most recent assistant turn from a transcript.

    Claude Code writes a JSONL transcript; each line is a message. We scan from
    the end for the last assistant message and concatenate its text parts. Robust
    to schema variation (``role``/``type`` keys, string or content-list bodies);
    returns "" if nothing parseable is found.
    """
    try:
        with open(transcript_path) as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    except OSError:
        return ""

    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("role") != "assistant" and rec.get("type") != "assistant":
            continue
        message = rec.get("message", rec)
        content = message.get("content", message.get("text", ""))
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = [
                blk.get("text", "")
                for blk in content
                if isinstance(blk, dict) and blk.get("type", "text") == "text"
            ]
            text = "".join(parts)
            if text:
                return text
    return ""


def _gate_output(payload: dict, chain, settings) -> dict:
    """Scan the finalized assistant turn; return a hook decision dict."""
    transcript_path = payload.get("transcript_path") or payload.get("transcriptPath")
    text = payload.get("assistant_text") or ""
    if not text and transcript_path:
        text = _extract_last_assistant_text(transcript_path)
    if not text:
        return {"action": "continue"}

    from spektralia.output_gate import scan_output

    result = scan_output(text, settings)
    if not result.flagged:
        return {"action": "continue"}

    chain.emit(
        "output_flagged",
        pattern_hash="",
        model_digest="",
        prompt_hash="",
        labels=result.labels,
        mode=settings.gate_outputs_mode,
    )
    if settings.gate_outputs_mode == "block":
        return {
            "decision": "block",
            "reason": f"Spektralia flagged sensitive content in the assistant turn: {result.reason}",
        }
    return {"action": "continue"}


def _write_session_event(payload: dict) -> None:
    """Best-effort: append the turn to the session-streams volume for Airlock (#114)."""
    try:
        from spektralia.sessions.writer import append_session_event

        session_id = payload.get("session_id") or payload.get("sessionId") or "unknown"
        transcript_path = payload.get("transcript_path") or payload.get("transcriptPath") or ""
        assistant_text = ""
        if transcript_path:
            assistant_text = _extract_last_assistant_text(transcript_path)
        append_session_event(
            session_id=str(session_id),
            source="claude-code",
            transcript_path=transcript_path,
            assistant_text=assistant_text,
        )
    except Exception:
        pass  # Never block session termination


def handle(payload: dict) -> dict:
    _write_session_event(payload)

    try:
        from spektralia.audit import AuditChain
        from spektralia.config import Settings

        s = Settings.from_env()
        chain = AuditChain(s.state_dir)
        chain.emit("session_end", pattern_hash="", model_digest="", prompt_hash="")

        decision = {"action": "continue"}
        if s.gate_outputs:
            decision = _gate_output(payload, chain, s)

        chain.close()
        return decision
    except Exception:
        pass  # Don't block session termination on audit errors

    return {"action": "continue"}


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read())
    except Exception:
        payload = {}

    print(json.dumps(handle(payload)))


if __name__ == "__main__":
    main()
