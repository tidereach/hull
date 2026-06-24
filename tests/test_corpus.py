"""Corpus-based regression tests for scanner detection.

Positive corpus:  tests/corpus/positive/  — each file should produce ≥1
                  detection whose label contains the stem (uppercased).

Negative corpus:  tests/corpus/negative/  — each file should produce zero
                  detections.

Injection corpus: tests/corpus/injection/ — obfuscated secrets; each file
                  should produce ≥1 detection after normalization.

Note — b64_key.txt is marked xfail: scan() does not call decode_and_rescan()
internally; base64-encoded payloads are only decoded by gate.py at the
orchestration layer.  The fixture is retained so the gap is visible and
tracked; see decode.py and gate.py (_gate_inner, line ~168).
"""

from pathlib import Path

import pytest

from spektralia.scanner import scan

CORPUS = Path(__file__).parent / "corpus"


def _label_from_filename(path: Path) -> str:
    return path.stem.upper()


def _all_files(subdir: str):
    return list((CORPUS / subdir).glob("*.txt"))


@pytest.mark.parametrize("path", _all_files("positive"), ids=lambda p: p.stem)
def test_positive(path):
    text = path.read_text()
    expected_label = _label_from_filename(path)
    detections = scan(text)
    labels = [d.label for d in detections]
    assert any(expected_label in l for l in labels), \
        f"{path.name}: expected label containing {expected_label!r}, got {labels}"


@pytest.mark.parametrize("path", _all_files("negative"), ids=lambda p: p.stem)
def test_negative(path):
    text = path.read_text()
    detections = scan(text)
    assert detections == [], \
        f"{path.name}: expected no detections, got {[d.label for d in detections]}"


_INJECTION_XFAIL = {
    "b64_key": "scan() does not call decode_and_rescan(); base64 unwrap only runs in gate._gate_inner.",
}


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(
            p,
            marks=pytest.mark.xfail(
                strict=True,
                reason=_INJECTION_XFAIL[p.stem],
            ),
        )
        if p.stem in _INJECTION_XFAIL
        else p
        for p in _all_files("injection")
    ],
    ids=lambda p: p.stem,
)
def test_injection(path):
    text = path.read_text()
    detections = scan(text)
    assert detections, \
        f"{path.name}: expected ≥1 detection, got none"
