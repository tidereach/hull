import base64
import gzip
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


def test_direct_gzip_magic_decompressed_and_scanned():
    """Literal gzip bytes (1f 8b ...) embedded in text are decompressed and rescanned."""
    secret = "please contact alice@example.com about the incident"
    gz = gzip.compress(secret.encode())
    assert gz[:2] == b"\x1f\x8b"
    # latin-1 is a lossless 1:1 byte<->codepoint mapping, so the hook can round-trip.
    text = "trailing binary paste: " + gz.decode("latin-1")
    dets = decode_and_rescan(text)
    assert "EMAIL_ENCODED" in {d.label for d in dets}


def test_base64_encoded_gzip_not_chased():
    """Documented single-level limit: a secret inside base64(gzip(...)) is NOT found.

    The base64 layer is decoded to gzip bytes and scanned as (replacement-folded)
    text — the gzip layer underneath is not unwrapped."""
    secret = "email bob@example.com hidden deep inside compressed padding padding"
    nested = base64.b64encode(gzip.compress(secret.encode())).decode()
    assert len(nested) >= 40
    dets = decode_and_rescan(f"blob: {nested}")
    assert "EMAIL_ENCODED" not in {d.label for d in dets}


def test_hex_with_invalid_utf8_bytes_does_not_crash():
    """Non-UTF-8 bytes in decoded hex are folded via errors='replace'; ASCII secrets survive."""
    raw = b"\xff\xfe key: alice@example.com \x80\x81 padding padding padding more"
    hex_str = raw.hex()
    assert len(hex_str) >= 64
    dets = decode_and_rescan(f"data: {hex_str}")
    assert "EMAIL_ENCODED" in {d.label for d in dets}


def test_odd_length_hex_run_skipped():
    """An odd-length hex run is skipped (cannot be byte-decoded) without error."""
    odd = "a" * 65  # matches the >=64 hex regex but has odd length
    assert len(odd) % 2 == 1
    dets = decode_and_rescan(f"id: {odd}")
    assert dets == []
