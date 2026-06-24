import base64
import json
from spektralia.decode import decode_and_rescan


def test_base64_encoded_email_detected():
    inner = json.dumps({"contact": "alice@example.com", "id": 1})
    padded = base64.b64encode(inner.encode()).decode()
    assert len(padded) >= 40
    text = f"data: {padded}"
    dets = decode_and_rescan(text)
    labels = {d.label for d in dets}
    assert "EMAIL_ENCODED" in labels


def test_hex_encoded_aws_key_detected():
    # Space after key ensures word boundary; pad to hit ≥64 hex chars (≥32 raw bytes)
    inner = "key: AKIAIOSFODNN7EXAMPLE leaked here padding padding padding"
    hex_str = inner.encode().hex()
    assert len(hex_str) >= 64
    dets = decode_and_rescan(f"data: {hex_str}")
    labels = {d.label for d in dets}
    assert "AWS_KEY_ENCODED" in labels


def test_clean_text_no_detections():
    dets = decode_and_rescan("Hello world no secrets here")
    assert dets == []


def test_short_base64_not_decoded():
    short = base64.b64encode(b"hello").decode()
    assert len(short) < 40
    dets = decode_and_rescan(f"x: {short}")
    assert dets == []
