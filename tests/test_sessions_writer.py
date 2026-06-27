"""Tests for spektralia.sessions.writer."""

from __future__ import annotations

import json

from spektralia.sessions.writer import _SCHEMA_KEYS, append_session_event


def test_writes_jsonl_line(tmp_path, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SESSION_STREAMS_DIR", str(tmp_path))
    result = append_session_event(
        session_id="abc123",
        source="claude-code",
        transcript_path="/work/session-streams/abc123.jsonl",
        assistant_text="hello world",
    )
    assert result is True
    line = (tmp_path / "abc123.jsonl").read_text().strip()
    event = json.loads(line)
    assert event["session_id"] == "abc123"
    assert event["source"] == "claude-code"
    assert event["event_type"] == "assistant_turn"
    assert event["assistant_text"] == "hello world"
    assert "ts" in event


def test_schema_keys_present(tmp_path, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SESSION_STREAMS_DIR", str(tmp_path))
    append_session_event(session_id="s1", source="copilot")
    event = json.loads((tmp_path / "s1.jsonl").read_text().strip())
    for key in _SCHEMA_KEYS:
        assert key in event, f"Missing schema key: {key}"


def test_appends_multiple_events(tmp_path, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SESSION_STREAMS_DIR", str(tmp_path))
    for i in range(3):
        append_session_event(session_id="s2", source="claude-code", assistant_text=str(i))
    lines = (tmp_path / "s2.jsonl").read_text().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[2])["assistant_text"] == "2"


def test_missing_dir_returns_false(monkeypatch, tmp_path):
    monkeypatch.setenv("SPEKTRALIA_SESSION_STREAMS_DIR", str(tmp_path / "nonexistent"))
    result = append_session_event(session_id="s3", source="claude-code")
    assert result is False


def test_separate_sessions_separate_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SPEKTRALIA_SESSION_STREAMS_DIR", str(tmp_path))
    append_session_event(session_id="a", source="claude-code")
    append_session_event(session_id="b", source="claude-code")
    assert (tmp_path / "a.jsonl").exists()
    assert (tmp_path / "b.jsonl").exists()
