"""Additional audit.py coverage: sink permission checks, sink implementations,
_choose_sink branches, state-load resilience, and rotate/purge edge cases.

test_audit_chain.py covers the happy-path chain, verify(), and the file/syslog
fallback; this file fills the remaining defensive and sink-specific branches.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import time
import types

import pytest

from spektralia.audit import (
    AppendOnlyFileSink,
    AuditChain,
    AuditRecord,
    AuditSink,
    JournaldSink,
    StdoutSink,
    SyslogSink,
    _choose_sink,
)


class DummySink(AuditSink):
    """In-memory sink so AuditChain never touches audit.jsonl on its own."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)


def _record(action="pass", wall_ns=None):
    r = AuditRecord(
        seq=1,
        prev_hash="0" * 64,
        action=action,
        labels=[],
        categories=[],
        confidence=0.0,
        pattern_hash="",
        model_digest="",
        prompt_hash="",
    )
    if wall_ns is not None:
        r.wall_ns = wall_ns
    return r


# ---------------------------------------------------------------------------
# AuditSink base + AppendOnlyFileSink permission checks
# ---------------------------------------------------------------------------


def test_base_sink_close_is_noop():
    """AuditSink.close() default is a no-op (must not raise)."""

    class MinimalSink(AuditSink):
        def write(self, record):
            pass

    MinimalSink().close()  # exercises the base close() body


def test_append_only_sink_rejects_group_writable(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    os.chmod(path, 0o666)
    with pytest.raises(PermissionError, match="group/world-writable"):
        AppendOnlyFileSink(path)


def test_append_only_sink_rejects_foreign_owner(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    os.chmod(path, 0o600)
    real_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
    with pytest.raises(PermissionError, match="not owned by current user"):
        AppendOnlyFileSink(path)


# ---------------------------------------------------------------------------
# SyslogSink and JournaldSink implementation bodies
# ---------------------------------------------------------------------------


def test_syslog_sink_write_and_close(monkeypatch):
    """Real SyslogSink body runs against a fake SysLogHandler (no /dev/log needed)."""

    class FakeSysLogHandler(logging.Handler):
        LOG_USER = 8

        def __init__(self, address=None, facility=None):
            super().__init__()
            self.closed = False

        def emit(self, record):
            pass

        def close(self):
            self.closed = True
            super().close()

    monkeypatch.setattr(logging.handlers, "SysLogHandler", FakeSysLogHandler)
    sink = SyslogSink(address="/dev/log")
    sink.write(_record("block"))
    sink.close()
    assert sink._handler.closed is True


def test_journald_sink_with_fake_module(monkeypatch):
    """JournaldSink imports systemd.journal and forwards to journal.send()."""
    sent: list = []
    fake_systemd = types.ModuleType("systemd")
    fake_journal = types.ModuleType("systemd.journal")
    fake_journal.send = lambda *a, **k: sent.append((a, k))
    fake_systemd.journal = fake_journal
    monkeypatch.setitem(sys.modules, "systemd", fake_systemd)
    monkeypatch.setitem(sys.modules, "systemd.journal", fake_journal)

    sink = JournaldSink()
    sink.write(_record("pass"))
    assert sent, "JournaldSink.write must call journal.send"


# ---------------------------------------------------------------------------
# _choose_sink: journald success and total fallback to stdout
# ---------------------------------------------------------------------------


def test_choose_sink_uses_journald_when_available(tmp_path, monkeypatch):
    class FakeJournald(AuditSink):
        def __init__(self):
            pass

        def write(self, record):
            pass

    monkeypatch.setattr("spektralia.audit.JournaldSink", FakeJournald)
    sink = _choose_sink(tmp_path)
    assert isinstance(sink, FakeJournald)


def test_choose_sink_falls_back_to_stdout_when_all_fail(tmp_path, monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("unavailable")

    monkeypatch.setattr("spektralia.audit.JournaldSink", boom)
    monkeypatch.setattr("spektralia.audit.AppendOnlyFileSink", boom)
    monkeypatch.setattr("spektralia.audit.SyslogSink", boom)
    sink = _choose_sink(tmp_path)
    assert isinstance(sink, StdoutSink)


# ---------------------------------------------------------------------------
# State load/save resilience
# ---------------------------------------------------------------------------


def test_load_state_corrupt_resets_to_genesis(tmp_path):
    (tmp_path / "audit.state").write_text("{not valid json")
    chain = AuditChain(tmp_path, sink=DummySink())
    rec = chain.emit("pass", pattern_hash="", model_digest="", prompt_hash="")
    assert rec.seq == 1
    assert rec.prev_hash == "0" * 64


def test_save_state_fsync_oserror_swallowed(tmp_path, monkeypatch):
    chain = AuditChain(tmp_path, sink=DummySink())
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("no fsync")))
    rec = chain.emit("pass", pattern_hash="", model_digest="", prompt_hash="")
    assert rec.seq == 1
    assert (tmp_path / "audit.state").exists()


# ---------------------------------------------------------------------------
# rotate / purge edge cases
# ---------------------------------------------------------------------------


def test_rotate_no_log_returns_zero(tmp_path):
    chain = AuditChain(tmp_path, sink=DummySink())
    assert chain.rotate(90) == 0


def test_purge_no_log_returns_zero(tmp_path):
    chain = AuditChain(tmp_path, sink=DummySink())
    assert chain.purge("2020-01-01") == 0


def _write_log(tmp_path, lines):
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")


def test_rotate_skips_blank_keeps_garbage_removes_old(tmp_path):
    now = time.time_ns()
    old = json.dumps({"action": "old", "wall_ns": int(time.time() - 200 * 86400) * 10**9})
    recent = json.dumps({"action": "recent", "wall_ns": now, "record_hash": "h", "seq": 9})
    _write_log(tmp_path, [old, "", "garbage-not-json", recent])

    chain = AuditChain(tmp_path, sink=DummySink())
    removed = chain.rotate(90)
    assert removed == 1
    kept = (tmp_path / "audit.jsonl").read_text()
    assert "garbage-not-json" in kept  # JSONDecodeError lines are kept
    assert "recent" in kept
    assert "old" not in kept


def test_rotate_removes_all_records(tmp_path):
    old1 = json.dumps({"action": "a", "wall_ns": int(time.time() - 300 * 86400) * 10**9})
    old2 = json.dumps({"action": "b", "wall_ns": int(time.time() - 250 * 86400) * 10**9})
    _write_log(tmp_path, [old1, old2])

    chain = AuditChain(tmp_path, sink=DummySink())
    removed = chain.rotate(90)
    assert removed == 2  # kept empty → anchor-update branch skipped


def test_purge_skips_blank_keeps_garbage_removes_old(tmp_path):
    import datetime

    old_ns = int(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC).timestamp() * 1e9)
    recent_ns = int(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC).timestamp() * 1e9)
    old = json.dumps({"action": "old", "wall_ns": old_ns})
    recent = json.dumps({"action": "recent", "wall_ns": recent_ns, "record_hash": "h", "seq": 4})
    _write_log(tmp_path, [old, "", "garbage-line", recent])

    chain = AuditChain(tmp_path, sink=DummySink())
    removed = chain.purge("2025-01-01")
    assert removed == 1
    kept = (tmp_path / "audit.jsonl").read_text()
    assert "garbage-line" in kept
    assert "recent" in kept
    assert '"action": "old"' not in kept
