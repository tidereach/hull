import json
import pytest
from pathlib import Path
from spektralia.audit import AuditChain, StdoutSink, AppendOnlyFileSink


def test_chain_integrity_100_records(tmp_path):
    sink_path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileSink(sink_path)
    chain = AuditChain(tmp_path, sink=sink)

    for i in range(100):
        chain.emit(
            "pass",
            labels=[],
            categories=[],
            confidence=0.0,
            pattern_hash="abc",
            model_digest="def",
            prompt_hash="ghi",
        )
    chain.close()

    records = []
    with open(sink_path) as fh:
        for line in fh:
            records.append(json.loads(line))

    assert len(records) == 100
    broken = chain.verify(records)
    assert broken == [], f"Chain broken at: {broken}"


def test_mutating_record_detected(tmp_path):
    sink_path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileSink(sink_path)
    chain = AuditChain(tmp_path, sink=sink)

    for i in range(5):
        chain.emit("pass", labels=[], categories=[], confidence=0.0,
                   pattern_hash="x", model_digest="y", prompt_hash="z")
    chain.close()

    records = []
    with open(sink_path) as fh:
        for line in fh:
            records.append(json.loads(line))

    # Mutate a record
    records[2]["confidence"] = 0.99

    broken = chain.verify(records)
    assert 2 in broken


def test_chain_survives_restart(tmp_path):
    """New chain anchors to previous session's last hash."""
    for session in range(2):
        sink_path = tmp_path / "audit.jsonl"
        sink = AppendOnlyFileSink(sink_path)
        chain = AuditChain(tmp_path, sink=sink)
        chain.emit("pass", labels=[], categories=[], confidence=0.0,
                   pattern_hash="x", model_digest="y", prompt_hash="z")
        chain.close()

    records = []
    with open(sink_path) as fh:
        for line in fh:
            records.append(json.loads(line))

    assert len(records) == 2
    # Second record's prev_hash must equal first record's record_hash
    assert records[1]["prev_hash"] == records[0]["record_hash"]


def test_audit_state_written(tmp_path):
    chain = AuditChain(tmp_path, sink=StdoutSink())
    chain.emit("pass", labels=[], categories=[], confidence=0.0,
               pattern_hash="x", model_digest="y", prompt_hash="z")
    state_path = tmp_path / "audit.state"
    assert state_path.exists()
    data = json.loads(state_path.read_text())
    assert "last_hash" in data
    assert data["seq"] == 1


def test_choose_sink_falls_back_to_syslog_then_file(tmp_path, monkeypatch):
    """_choose_sink must try: journald → syslog → file → stdout."""
    from spektralia.audit import _choose_sink, SyslogSink, AppendOnlyFileSink

    # Make JournaldSink raise (it always does in test environments without systemd)
    # Make SyslogSink succeed — patch SyslogSink.__init__ to succeed without /dev/log
    syslog_constructed = []

    class FakeSyslogSink(SyslogSink):
        def __init__(self):
            syslog_constructed.append(True)
            # Don't call super().__init__ — avoid real syslog connection
            import logging.handlers
            self._handler = logging.handlers.MemoryHandler(capacity=100)
            self._logger = logging.getLogger("spektralia.audit.test")
            self._logger.addHandler(self._handler)

        def write(self, record):
            pass

    monkeypatch.setattr("spektralia.audit.SyslogSink", FakeSyslogSink)

    sink = _choose_sink(tmp_path)
    assert syslog_constructed, "SyslogSink must be tried when JournaldSink fails"
    assert isinstance(sink, FakeSyslogSink), f"Expected FakeSyslogSink, got {type(sink)}"


def test_choose_sink_falls_back_to_file_when_syslog_fails(tmp_path, monkeypatch):
    """_choose_sink falls through to AppendOnlyFileSink when syslog also fails."""
    from spektralia.audit import _choose_sink, AppendOnlyFileSink

    def fail_syslog_init(self):
        raise OSError("no /dev/log")

    monkeypatch.setattr("spektralia.audit.SyslogSink.__init__", fail_syslog_init)

    sink = _choose_sink(tmp_path)
    assert isinstance(sink, AppendOnlyFileSink), \
        f"Expected AppendOnlyFileSink when syslog fails, got {type(sink)}"
