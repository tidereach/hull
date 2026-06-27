"""Gating of model outputs / assistant turns (#47).

Spektralia's primary gate scans the *outbound* payload (user prompt + context)
before a cloud call. This module adds the complementary surface: scanning a
*finalized assistant turn* so a model that echoes back sensitive content it was
given — or synthesizes new sensitive output — is caught before that turn is
acted on downstream.

Design decisions (issue #47, "scope to be refined"):

- **Finalized turns, not streaming.** We scan complete assistant turns, not the
  token stream. Streaming interception would add per-token latency and has no
  clean hook surface; the Stop hook gives us the whole turn at a natural boundary.
- **Deterministic pipeline, classifier deferred.** Output scanning reuses the
  same normalize → scan path as the outbound gate (regex + entropy + decoded
  payloads + opt-in NER) but deliberately omits the Ollama classifier: running
  the model on every assistant turn would add perceptible interactive latency
  (the issue's explicit performance budget). Classifier-based output gating is a
  documented v3 consideration.
- **Opt-in, warn by default.** Gated behind ``Settings.gate_outputs`` (default
  ``False``). ``gate_outputs_mode`` is ``"warn"`` (audit only) or ``"block"``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Settings
from .decode import decode_and_rescan
from .entropy import find_high_entropy
from .ner import build_ner_backend, scan_entities
from .scanner import Detection, scan

# Audit-visible markers that are not themselves sensitive output.
_NON_SENSITIVE_LABELS = frozenset({"OBFUSCATION_CHAR"})


@dataclass
class OutputScanResult:
    """Result of scanning a finalized assistant turn."""

    flagged: bool
    labels: list[str] = field(default_factory=list)
    reason: str = ""


def scan_output(text: str, settings: Settings | None = None) -> OutputScanResult:
    """Scan a finalized assistant turn for sensitive content.

    Runs the deterministic detection pipeline (regex + entropy + decoded payloads,
    plus NER when ``settings.ner_enabled``). Returns labels only — never values —
    so the result is safe to log and surface.
    """
    s = settings or Settings.from_env()
    if not text:
        return OutputScanResult(flagged=False)

    detections: list[Detection] = scan(text)
    detections.extend(find_high_entropy(text))
    detections.extend(decode_and_rescan(text))

    if s.ner_enabled:
        try:
            detections.extend(scan_entities(text, build_ner_backend(s.ner_model)))
        except Exception:
            pass  # NER must never crash output scanning

    labels = sorted({d.label for d in detections if d.label not in _NON_SENSITIVE_LABELS})
    if not labels:
        return OutputScanResult(flagged=False)
    return OutputScanResult(
        flagged=True,
        labels=labels,
        reason=f"output rule({','.join(labels)})",
    )
