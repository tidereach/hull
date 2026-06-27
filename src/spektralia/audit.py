from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import stat
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64
_OWNER_DIR_MODE = 0o700
_OWNER_FILE_MODE = 0o600


@dataclass
class AuditRecord:
    seq: int
    prev_hash: str
    action: str
    labels: list[str]
    categories: list[str]
    confidence: float
    pattern_hash: str
    model_digest: str
    prompt_hash: str
    wall_ns: int = field(default_factory=time.time_ns)
    mono_ns: int = field(default_factory=time.monotonic_ns)
    extra: dict[str, Any] = field(default_factory=dict)
    record_hash: str = field(default="", init=False)

    def __post_init__(self) -> None:
        self.record_hash = self._compute_hash()

    def _canonical_dict(self) -> dict:
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "action": self.action,
            "labels": sorted(self.labels),
            "categories": sorted(self.categories),
            "confidence": self.confidence,
            "pattern_hash": self.pattern_hash,
            "model_digest": self.model_digest,
            "prompt_hash": self.prompt_hash,
            "wall_ns": self.wall_ns,
            "mono_ns": self.mono_ns,
        }

    def _compute_hash(self) -> str:
        payload = json.dumps(self._canonical_dict(), sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            **self._canonical_dict(),
            "record_hash": self.record_hash,
            **self.extra,
        }

    @classmethod
    def from_dict(cls, rec: dict) -> AuditRecord:
        return cls(
            seq=rec["seq"],
            prev_hash=rec["prev_hash"],
            action=rec["action"],
            labels=rec.get("labels", []),
            categories=rec.get("categories", []),
            confidence=rec.get("confidence", 0.0),
            pattern_hash=rec.get("pattern_hash", ""),
            model_digest=rec.get("model_digest", ""),
            prompt_hash=rec.get("prompt_hash", ""),
            wall_ns=rec["wall_ns"],
            mono_ns=rec["mono_ns"],
        )


class AuditSink(ABC):
    @abstractmethod
    def write(self, record: AuditRecord) -> None: ...

    def close(self) -> None:
        pass


class StdoutSink(AuditSink):
    def __init__(self) -> None:
        print("WARNING: spektralia audit sink is stdout (dev only)", file=sys.stderr)

    def write(self, record: AuditRecord) -> None:
        print(json.dumps(record.to_dict()), flush=True)


class AppendOnlyFileSink(AuditSink):
    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=_OWNER_DIR_MODE)

        # Security: refuse if file is writable by non-owner
        if path.exists():
            st = path.stat()
            if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise PermissionError(f"Audit log {path} is group/world-writable")
            if st.st_uid != os.getuid():
                raise PermissionError(f"Audit log {path} is not owned by current user")

        self._fh = open(path, "a", buffering=1)  # line-buffered
        os.chmod(path, _OWNER_FILE_MODE)  # enforce regardless of umask (Ubuntu default is 0002)

    def write(self, record: AuditRecord) -> None:
        line = json.dumps(record.to_dict()) + "\n"
        self._fh.write(line)
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()


class JournaldSink(AuditSink):
    """Write to systemd journal if available."""

    def __init__(self) -> None:
        try:
            from systemd import journal

            self._journal = journal
        except ImportError:
            raise RuntimeError("systemd.journal not available")

    def write(self, record: AuditRecord) -> None:
        self._journal.send(
            json.dumps(record.to_dict()),
            SYSLOG_IDENTIFIER="spektralia",
            PRIORITY=6,
        )


class SyslogSink(AuditSink):
    """Write to syslog via logging.handlers.SysLogHandler."""

    def __init__(self, address: str = "/dev/log") -> None:
        import logging.handlers

        handler = logging.handlers.SysLogHandler(
            address=address,
            facility=logging.handlers.SysLogHandler.LOG_USER,
        )
        self._handler = handler
        self._logger = logging.getLogger("spektralia.audit")
        if handler not in self._logger.handlers:
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def write(self, record: AuditRecord) -> None:
        self._logger.info("spektralia_audit %s", json.dumps(record.to_dict()))

    def close(self) -> None:
        self._handler.close()


def _choose_sink(state_dir: Path) -> AuditSink:
    """Auto-detect best sink: journald > append-file > syslog > stdout.

    Syslog is a last resort: it cannot be read by audit-verify. The file
    sink is preferred over syslog so that audit-verify and manual inspection
    via `tail ~/.spektralia/audit.jsonl` always work.
    """
    try:
        sink: AuditSink = JournaldSink()
        logger.info("audit: using journald sink")
        return sink
    except Exception:
        pass

    log_path = state_dir / "audit.jsonl"
    try:
        sink = AppendOnlyFileSink(log_path)
        logger.info("audit: using append-only file sink at %s", log_path)
        return sink
    except Exception:
        pass

    try:
        sink = SyslogSink()
        logger.info("audit: using syslog sink")
        return sink
    except Exception:
        pass

    return StdoutSink()


class AuditChain:
    """Persistent hash-chained audit log."""

    _STATE_FILE = "audit.state"

    def __init__(self, state_dir: Path, sink: AuditSink | None = None) -> None:
        self._state_dir = state_dir
        state_dir.mkdir(parents=True, exist_ok=True, mode=_OWNER_DIR_MODE)
        self._state_path = state_dir / self._STATE_FILE
        self._sink = sink or _choose_sink(state_dir)
        self._seq = 0
        self._prev_hash = self._load_state()

    def _load_state(self) -> str:
        if self._state_path.exists():
            try:
                data = json.loads(self._state_path.read_text())
                self._seq = data.get("seq", 0)
                return str(data.get("last_hash", _GENESIS_HASH))
            except Exception:
                return _GENESIS_HASH
        return _GENESIS_HASH

    def _save_state(self, record: AuditRecord) -> None:
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seq": record.seq, "last_hash": record.record_hash}))
        tmp.replace(self._state_path)
        try:
            fd = os.open(str(self._state_path), os.O_RDONLY)
            os.fsync(fd)
            os.close(fd)
        except OSError:
            pass

    def emit(
        self,
        action: str,
        *,
        labels: list[str] | None = None,
        categories: list[str] | None = None,
        confidence: float = 0.0,
        pattern_hash: str = "",
        model_digest: str = "",
        prompt_hash: str = "",
        **extra,
    ) -> AuditRecord:
        self._seq += 1
        record = AuditRecord(
            seq=self._seq,
            prev_hash=self._prev_hash,
            action=action,
            labels=labels or [],
            categories=categories or [],
            confidence=confidence,
            pattern_hash=pattern_hash,
            model_digest=model_digest,
            prompt_hash=prompt_hash,
            extra=extra,
        )
        self._sink.write(record)
        self._prev_hash = record.record_hash
        self._save_state(record)
        return record

    def verify(self, records: list[dict]) -> list[int]:
        """Return indices of records where the chain breaks."""
        broken: list[int] = []
        for i, rec in enumerate(records):
            expected_hash = AuditRecord.from_dict(rec).record_hash
            if expected_hash != rec.get("record_hash"):
                broken.append(i)
        return broken

    def _prune_log(self, cutoff_ns: int, anchor_action: str, **anchor_extra) -> int:
        """Filter the file-based audit log, keeping records with wall_ns >= cutoff_ns.

        Rewrites the log in place, resets chain state to the last kept record,
        and emits an anchor event. Returns the number of records removed.
        Only operates if audit.jsonl exists; returns 0 otherwise.
        """
        log_path = self._state_dir / "audit.jsonl"
        if not log_path.exists():
            return 0
        kept: list[str] = []
        removed = 0
        with open(log_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("wall_ns", 0) >= cutoff_ns:
                        kept.append(line)
                    else:
                        removed += 1
                except json.JSONDecodeError:
                    kept.append(line)
        if removed:
            tmp = log_path.with_suffix(".tmp")
            tmp.write_text("\n".join(kept) + ("\n" if kept else ""))
            tmp.replace(log_path)
            if kept:
                last = json.loads(kept[-1])
                self._prev_hash = last.get("record_hash", _GENESIS_HASH)
                self._seq = last.get("seq", self._seq)
            self.emit(
                anchor_action,
                pattern_hash="",
                model_digest="",
                prompt_hash="",
                removed=removed,
                **anchor_extra,
            )
        return removed

    def rotate(self, keep_days: int) -> int:
        """Remove records older than keep_days from the file-based audit log.

        Returns number of records removed. Emits chain_anchor_after_rotate event.
        Only operates on append-only file sinks; is a no-op otherwise.
        """
        cutoff_ns = int((time.time() - keep_days * 86400) * 1e9)
        return self._prune_log(cutoff_ns, "chain_anchor_after_rotate", keep_days=keep_days)

    def purge(self, before_date: str) -> int:
        """Remove records before the given ISO date (YYYY-MM-DD) from the file-based log.

        Returns number of records removed. Emits chain_anchor_after_purge event.
        Only operates on append-only file sinks; is a no-op otherwise.
        """
        try:
            cutoff_dt = datetime.date.fromisoformat(before_date)
        except ValueError as exc:
            raise ValueError(f"Invalid date format '{before_date}'; expected YYYY-MM-DD") from exc
        cutoff_ns = int(
            datetime.datetime(
                cutoff_dt.year,
                cutoff_dt.month,
                cutoff_dt.day,
                tzinfo=datetime.UTC,
            ).timestamp()
            * 1e9
        )
        return self._prune_log(cutoff_ns, "chain_anchor_after_purge", before_date=before_date)

    def close(self) -> None:
        self._sink.close()
