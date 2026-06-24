from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .anomaly import AnomalyDetector, FreezeSwitch
from .audit import AuditChain
from .cache import LRUCache
from .canary import CanaryResult, run_canary
from .classifier import ClassifierResult, classify
from .config import Settings
from .decode import decode_and_rescan
from .entropy import find_high_entropy
from .errors import SensitiveDataError
from .heartbeat import HeartbeatEmitter
from .integrity import compute_pattern_hash, fetch_model_digest, get_integrity_report
from .ollama_trust import build_client
from .sanitizer import Sanitized, sanitize
from .scanner import Detection, scan


logger = logging.getLogger(__name__)


@dataclass
class GateResult:
    """Public result of a gate() call that passed."""

    sanitized_text: str
    detections: list[Detection]  # labels + spans only, no values
    classifier_result: ClassifierResult | None
    blocked: bool = False
    block_reason: str = ""


class Gate:
    """Singleton-per-config gate instance."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        s = self._settings
        self._state_dir = s.state_dir
        self._state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        self._chain = AuditChain(self._state_dir)
        self._anomaly = AnomalyDetector(
            window_seconds=s.anomaly_window_seconds,
            classifier_unavailable_rate_threshold=s.classifier_unavailable_rate_threshold,
            rule_classifier_disagreement_rate_threshold=s.rule_classifier_disagreement_rate_threshold,
        )
        self._freeze = FreezeSwitch(s.freeze_path)
        self._cache = LRUCache(maxsize=s.cache_size)
        self._lock = threading.Lock() if s.thread_safe else None

        self._pattern_hash = compute_pattern_hash()
        self._client: httpx.Client | None = None
        self._model_digest = ""
        self._last_canary: CanaryResult | None = None

        integrity = get_integrity_report(None, s.ollama_model)
        self._prompt_hash = integrity["prompt_hash"]

        self._heartbeat = HeartbeatEmitter(
            chain=self._chain,
            pattern_hash=self._pattern_hash,
            model_digest=self._model_digest,
            prompt_hash=self._prompt_hash,
            heartbeat_seconds=s.heartbeat_seconds,
            heartbeat_every_n_calls=s.heartbeat_every_n_calls,
        )

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            s = self._settings
            self._client = build_client(
                ollama_url=s.ollama_url,
                ollama_socket=s.ollama_socket,
                auth_header=s.ollama_auth_header,
                model=s.ollama_model,
            )
            self._model_digest = fetch_model_digest(self._client, s.ollama_model)
        return self._client

    def freeze(self) -> None:
        """Freeze the gate and invalidate all cached verdicts."""
        self._freeze.set_frozen(True)
        self._cache.invalidate_all()

    def unfreeze(self) -> None:
        """Unfreeze the gate and invalidate all cached verdicts."""
        self._freeze.set_frozen(False)
        self._cache.invalidate_all()

    def _run_canary(self) -> None:
        result = run_canary(scan)
        self._last_canary = result
        if not result.passed:
            self._anomaly.record("canary_drift")
            self._chain.emit(
                "canary_drift",
                pattern_hash=self._pattern_hash,
                model_digest=self._model_digest,
                prompt_hash=self._prompt_hash,
                failures=result.failures,
            )
            self._cache.invalidate_all()

    def _emit(self, action: str, detections: list[Detection], cr: ClassifierResult | None, **extra) -> None:
        labels = [d.label for d in detections]
        categories = cr.categories if cr else []
        confidence = cr.confidence if cr else 0.0
        self._chain.emit(
            action,
            labels=labels,
            categories=categories,
            confidence=confidence,
            pattern_hash=self._pattern_hash,
            model_digest=self._model_digest,
            prompt_hash=self._prompt_hash,
            **extra,
        )

    async def gate(self, text: str, settings: Settings | None = None) -> GateResult:
        s = settings or self._settings
        lock = self._lock

        if lock:
            lock.acquire()
        try:
            return await self._gate_inner(text, s)
        finally:
            if lock:
                lock.release()

    async def _gate_inner(self, text: str, s: Settings) -> GateResult:
        # Check freeze
        frozen, freeze_reason = self._freeze.is_frozen()
        if frozen or self._anomaly.should_freeze:
            reason = freeze_reason or self._anomaly.freeze_reason or "gate_frozen"
            self._emit("gate_frozen", [], None, reason=reason)
            raise SensitiveDataError(reason=reason)

        # Input size cap
        if len(text) > s.max_input_chars:
            self._emit("block", [], None, reason="input_too_large")
            raise SensitiveDataError(reason="input_too_large", labels=("input_too_large",))

        # Detection pipeline
        detections = scan(text)
        detections.extend(find_high_entropy(text))
        detections.extend(decode_and_rescan(text))

        # Check for regex timeout — fail closed
        rule_labels = {d.label for d in detections}
        if "REGEX_TIMEOUT" in rule_labels:
            self._emit("block", detections, None, reason="REGEX_TIMEOUT")
            raise SensitiveDataError(reason="REGEX_TIMEOUT", labels=tuple(rule_labels))

        rule_hit = any(d.label not in ("OBFUSCATION_CHAR",) for d in detections)

        # Sanitize before classifier
        sanitized = sanitize(text, detections)

        # Cache check — keyed on sanitized text so inputs that differ only in secret value
        # but produce the same sanitized form share a cache entry
        config_hash = s.config_hash()
        cache_key = LRUCache.make_key(
            sanitized.text,
            config_hash,
            pattern_hash=self._pattern_hash,
            model_digest=self._model_digest,
            prompt_hash=self._prompt_hash,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            if cached.get("blocked"):
                raise SensitiveDataError(
                    reason=cached["reason"],
                    labels=tuple(cached.get("labels", [])),
                    categories=tuple(cached.get("categories", [])),
                )
            return GateResult(
                sanitized_text=cached["sanitized_text"],
                detections=[],
                classifier_result=None,
            )

        # Classify
        cr: ClassifierResult | None = None
        try:
            client = self._get_client()
            cr = classify(
                sanitized.text,
                client=client,
                model=s.ollama_model,
                mode=s.classifier_mode,
                sensitivity_threshold=s.sensitivity_threshold,
                framing_disagreement_threshold=s.framing_disagreement_threshold,
                timeout=s.classifier_timeout_seconds,
            )
        except Exception as e:
            logger.warning("classifier error: %s", e)
            if not s.fail_open:
                self._anomaly.record("classifier_unavailable")
                self._emit("classifier_unavailable", detections, None)
                if self._anomaly.should_freeze:
                    self._chain.emit(
                        "gate_frozen_auto",
                        pattern_hash=self._pattern_hash,
                        model_digest=self._model_digest,
                        prompt_hash=self._prompt_hash,
                    )
                raise SensitiveDataError(
                    reason="classifier_unavailable",
                    labels=tuple(rule_labels),
                )
            cr = None

        # Classifier unavailable category
        if cr and "classifier_unavailable" in cr.categories:
            self._anomaly.record("classifier_unavailable")
            if not s.fail_open:
                self._emit("block", detections, cr, reason="classifier_unavailable")
                raise SensitiveDataError(
                    reason="classifier_unavailable",
                    labels=tuple(rule_labels),
                    categories=tuple(cr.categories),
                )

        # Framing disagreement audit event
        if cr and cr.framing_disagreement:
            self._anomaly.record("framing_disagreement")
            self._chain.emit(
                "framing_disagreement",
                labels=[d.label for d in detections],
                categories=cr.categories,
                confidence=cr.confidence,
                pattern_hash=self._pattern_hash,
                model_digest=self._model_digest,
                prompt_hash=self._prompt_hash,
                min_confidence=cr.min_confidence,
            )

        classifier_high = cr is not None and cr.sensitive and cr.confidence >= s.sensitivity_threshold

        # Rule/classifier disagreement
        if rule_hit and cr and not cr.sensitive:
            self._anomaly.record("rule_classifier_disagreement")
            self._emit("rule_classifier_disagreement", detections, cr)
        if not rule_hit and classifier_high:
            self._anomaly.record("rule_classifier_disagreement")
            self._emit("rule_classifier_disagreement", detections, cr)

        # Block decision: rule_hit OR classifier_high
        should_block = rule_hit or classifier_high

        if should_block:
            if s.mode == "soft" and classifier_high and not rule_hit:
                # Soft mode: prompt user (hooks handle the actual prompting)
                categories_frozen = frozenset(cr.categories if cr else [])
                if self._anomaly.check_mutation_pattern(categories_frozen):
                    self._emit("mutation_pattern_detected", detections, cr)
                    raise SensitiveDataError(
                        reason="mutation_pattern_detected",
                        labels=tuple(rule_labels),
                        categories=tuple(cr.categories if cr else []),
                        confidence=cr.confidence if cr else 0.0,
                    )
                # Return a GateResult with blocked=True for soft-mode hooks to handle
                self._emit("warn", detections, cr)
                result = GateResult(
                    sanitized_text=sanitized.text,
                    detections=detections,
                    classifier_result=cr,
                    blocked=True,
                    block_reason=_format_block_reason(rule_labels, cr),
                )
                self._cache.set(cache_key, {
                    "blocked": True,
                    "reason": result.block_reason,
                    "labels": list(rule_labels),
                    "categories": list(cr.categories if cr else []),
                })
                return result

            # Hard block
            block_reason = _format_block_reason(rule_labels, cr)
            self._emit("block", detections, cr, reason=block_reason)
            self._cache.set(cache_key, {
                "blocked": True,
                "reason": block_reason,
                "labels": list(rule_labels),
                "categories": list(cr.categories if cr else []),
            })
            raise SensitiveDataError(
                reason=block_reason,
                labels=tuple(rule_labels),
                categories=tuple(cr.categories if cr else []),
                confidence=cr.confidence if cr else 0.0,
            )

        # Pass
        self._emit("pass", detections, cr)
        self._cache.set(cache_key, {
            "blocked": False,
            "sanitized_text": sanitized.text,
        })

        self._heartbeat.tick(self._anomaly, self._last_canary)

        return GateResult(
            sanitized_text=sanitized.text,
            detections=detections,
            classifier_result=cr,
        )


def _format_block_reason(rule_labels: set[str], cr: ClassifierResult | None) -> str:
    parts = []
    if rule_labels:
        parts.append(f"rule({','.join(sorted(rule_labels))})")
    if cr and cr.sensitive:
        parts.append(f"classifier({cr.confidence:.2f}, {cr.categories})")
    return "Blocked: " + " + ".join(parts) if parts else "Blocked"


# Module-level default gate instance (lazy)
_default_gate: Gate | None = None
_gate_lock = threading.Lock()


def _get_default_gate(settings: Settings | None = None) -> Gate:
    global _default_gate
    with _gate_lock:
        if _default_gate is None or settings is not None:
            _default_gate = Gate(settings)
        return _default_gate


async def gate(text: str, settings: Settings | None = None) -> GateResult:
    """Async gate entry point."""
    g = _get_default_gate(settings)
    return await g.gate(text, settings)


def gate_sync(text: str, settings: Settings | None = None) -> GateResult:
    """Synchronous wrapper. Raises if called inside a running event loop."""
    try:
        loop = asyncio.get_running_loop()
        if loop.is_running():
            raise RuntimeError(
                "gate_sync() called inside a running event loop. Use await gate() instead."
            )
    except RuntimeError as e:
        if "no running event loop" not in str(e).lower() and "gate_sync" not in str(e):
            raise
    return asyncio.run(gate(text, settings))
