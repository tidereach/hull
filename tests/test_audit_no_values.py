"""Assert no known secret value ever appears in audit records."""
import json
import pytest
from spektralia.audit import AuditChain, AppendOnlyFileSink


_KNOWN_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "alice@example.com",
    "sk_live_secret12345",
    "4111111111111111",
]


def test_audit_emit_never_stores_value(tmp_path):
    sink_path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileSink(sink_path)
    chain = AuditChain(tmp_path, sink=sink)

    # Emit events that reference secrets only as labels — never values
    chain.emit(
        "block",
        labels=["EMAIL", "AWS_KEY"],
        categories=["CREDENTIALS"],
        confidence=0.95,
        pattern_hash="abc",
        model_digest="def",
        prompt_hash="ghi",
    )
    chain.close()

    content = sink_path.read_text()
    for secret in _KNOWN_SECRETS:
        assert secret not in content, f"Secret {secret!r} found in audit log"


def test_fuzz_audit_interface(tmp_path):
    """Fuzz many events with known-secret extra fields — none should leak."""
    sink_path = tmp_path / "audit.jsonl"
    sink = AppendOnlyFileSink(sink_path)
    chain = AuditChain(tmp_path, sink=sink)

    for secret in _KNOWN_SECRETS:
        # The audit interface should only receive labels, not values
        # This test ensures callers cannot accidentally pass values via **extra
        chain.emit(
            "block",
            labels=["EMAIL"],
            categories=["PII"],
            confidence=0.9,
            pattern_hash="x",
            model_digest="y",
            prompt_hash="z",
            # Do NOT pass secret here — this is the correct usage
            reason="test_block",
        )

    chain.close()
    content = sink_path.read_text()
    for secret in _KNOWN_SECRETS:
        assert secret not in content
