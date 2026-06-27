"""Session-stream writer — appends normalized JSONL turn events.

Called from the Stop hook after each agent turn. Writes to the
session-streams named volume so the Airlock ingester (#114) can tail it.

The writer is best-effort: a missing directory or permission error is
logged to stderr and silently dropped so it never blocks session termination.

Event schema (one JSON line per call):
  {
    "ts":              float   # Unix timestamp (seconds)
    "session_id":      str     # Opaque session identifier from hook payload
    "source":          str     # e.g. "claude-code", "copilot"
    "event_type":      str     # "assistant_turn"
    "transcript_path": str     # Path to the JSONL transcript file (may be "")
    "assistant_text":  str     # Extracted assistant turn text (may be "")
  }
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_STREAMS_DIR = "/work/session-streams"

_SCHEMA_KEYS = ("ts", "session_id", "source", "event_type", "transcript_path", "assistant_text")


def _streams_dir() -> Path:
    return Path(os.environ.get("SPEKTRALIA_SESSION_STREAMS_DIR", _DEFAULT_STREAMS_DIR))


def append_session_event(
    *,
    session_id: str,
    source: str,
    event_type: str = "assistant_turn",
    transcript_path: str = "",
    assistant_text: str = "",
) -> bool:
    """Append one JSONL event to <streams_dir>/<session_id>.jsonl.

    Returns True on success, False on any error.
    """
    streams = _streams_dir()
    if not streams.is_dir():
        return False

    event = {
        "ts": time.time(),
        "session_id": session_id,
        "source": source,
        "event_type": event_type,
        "transcript_path": transcript_path,
        "assistant_text": assistant_text,
    }
    target = streams / f"{session_id}.jsonl"
    try:
        with open(target, "a") as fh:
            fh.write(json.dumps(event) + "\n")
        return True
    except OSError as exc:
        logger.debug("session writer: could not write to %s: %s", target, exc)
        return False
