from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal

_bool_env = lambda v: v.lower() in ("1", "true", "yes")  # noqa: E731


def _coerce_paths(data: dict) -> None:
    """Coerce string path fields to Path objects in place."""
    for fname in ("freeze_path", "state_dir", "hook_manifest_path"):
        if fname in data and data[fname] is not None:
            data[fname] = Path(data[fname])
    if "sandbox_config_paths" in data:
        data["sandbox_config_paths"] = tuple(data["sandbox_config_paths"])


@dataclass
class Settings:
    # Ollama
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_socket: str | None = None
    ollama_auth_header: str | None = None
    ollama_model: str = "llama3.1:8b"
    ollama_model_digest: str | None = None
    ollama_telemetry_accepted: bool = False

    # Classifier
    classifier_mode: Literal["strict", "fast"] = "strict"
    classifier_timeout_seconds: float = 10.0
    framing_disagreement_threshold: float = 0.3
    sensitivity_threshold: float = 0.7

    # Gate
    mode: Literal["strict", "soft"] = "strict"
    fail_open: bool = False
    max_input_chars: int = 100_000
    thread_safe: bool = False

    # Anomaly / freeze
    freeze_path: Path = field(default_factory=lambda: Path.home() / ".spektralia" / "FREEZE")
    anomaly_window_seconds: int = 300
    classifier_unavailable_rate_threshold: float = 0.5
    rule_classifier_disagreement_rate_threshold: float = 0.5

    # Canary
    canary_interval_seconds: int = 3600

    # Heartbeat
    heartbeat_seconds: int = 300
    heartbeat_every_n_calls: int = 100

    # Cache
    cache_size: int = 1024

    # Memory
    mlock_secrets: bool = False

    # Sandbox (execution-plane neighbor: Fence or cplt) — see docs/SANDBOX_ALTERNATIVES.md
    sandbox_backend: Literal["none", "fence", "cplt"] = "none"
    sandbox_config_paths: tuple[str, ...] = ()
    sandbox_config_hash: str | None = None

    # Hook integrity: detect tampered hook scripts post-install (see hook_manifest.py).
    # "off" skips the check; "warn" emits an audit event but allows the session;
    # "block" refuses to start the session on any digest mismatch.
    hook_integrity_mode: Literal["off", "warn", "block"] = "warn"
    hook_manifest_path: Path | None = None

    # Internal path
    state_dir: Path = field(default_factory=lambda: Path.home() / ".spektralia")

    # Normalization
    normalization_map_version: int = 1

    # Contextual PII / NER (opt-in; requires the `ner` extra). Both fields are
    # policy-affecting — toggling NER or its model changes the scan verdict, so
    # they stay IN config_hash() and invalidate the cache when changed.
    ner_enabled: bool = False
    ner_model: str = "en_core_web_sm"

    # These fields are NOT policy-affecting (not in config_hash)
    _non_policy: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "freeze_path",
                "state_dir",
                "ollama_socket",
                "ollama_auth_header",
                "ollama_telemetry_accepted",
                "thread_safe",
                "mlock_secrets",
                "canary_interval_seconds",
                "heartbeat_seconds",
                "heartbeat_every_n_calls",
                "anomaly_window_seconds",
                "classifier_timeout_seconds",
                # Sandbox backend selection governs the execution-plane neighbor, not
                # the content-scan verdict, so it must NOT enter config_hash()/the cache key.
                "sandbox_backend",
                "sandbox_config_paths",
                "sandbox_config_hash",
                # Hook integrity governs the agent-side hook surface, not the
                # content-scan verdict, so it stays out of config_hash()/the cache key.
                "hook_integrity_mode",
                "hook_manifest_path",
                "_non_policy",
            }
        ),
        repr=False,
        compare=False,
    )

    @classmethod
    def from_env(cls, **overrides) -> Settings:
        # TOML discovery: local files first, then global
        toml_data: dict = {}
        for candidate in (
            Path(".spektralia.toml"),
            Path("spektralia.toml"),
            Path.home() / ".spektralia" / "config.toml",
        ):
            if candidate.exists():
                with open(candidate, "rb") as fh:
                    raw = tomllib.load(fh)
                # Accept both [spektralia] section and top-level keys
                toml_data = raw.get("spektralia", raw)
                break

        # Coerce Path fields from TOML
        _coerce_paths(toml_data)

        env: dict[str, object] = {}
        mapping: dict[str, tuple[str, Callable[[str], object]]] = {
            "SPEKTRALIA_OLLAMA_URL": ("ollama_url", str),
            "SPEKTRALIA_OLLAMA_SOCKET": ("ollama_socket", str),
            "SPEKTRALIA_OLLAMA_MODEL": ("ollama_model", str),
            "SPEKTRALIA_OLLAMA_MODEL_DIGEST": ("ollama_model_digest", str),
            "SPEKTRALIA_CLASSIFIER_MODE": ("classifier_mode", str),
            "SPEKTRALIA_SENSITIVITY_THRESHOLD": ("sensitivity_threshold", float),
            "SPEKTRALIA_MODE": ("mode", str),
            "SPEKTRALIA_FAIL_OPEN": ("fail_open", _bool_env),
            "SPEKTRALIA_MAX_INPUT_CHARS": ("max_input_chars", int),
            "SPEKTRALIA_MLOCK_SECRETS": ("mlock_secrets", _bool_env),
            "SPEKTRALIA_CLASSIFIER_TIMEOUT_SECONDS": ("classifier_timeout_seconds", float),
            "SPEKTRALIA_STATE_DIR": ("state_dir", Path),
            "SPEKTRALIA_SANDBOX_BACKEND": ("sandbox_backend", str),
            "SPEKTRALIA_SANDBOX_CONFIG_HASH": ("sandbox_config_hash", str),
            "SPEKTRALIA_HOOK_INTEGRITY_MODE": ("hook_integrity_mode", str),
            "SPEKTRALIA_HOOK_MANIFEST_PATH": ("hook_manifest_path", Path),
            "SPEKTRALIA_NER_ENABLED": ("ner_enabled", _bool_env),
            "SPEKTRALIA_NER_MODEL": ("ner_model", str),
        }
        for env_key, (attr, coerce) in mapping.items():
            val = os.environ.get(env_key)
            if val is not None:
                try:
                    env[attr] = coerce(val)
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Invalid {env_key}={val!r}: {e}") from e

        # Precedence: overrides > env vars > TOML > defaults
        merged = {**toml_data, **env, **overrides}
        return cls(**merged)

    @classmethod
    def from_toml(cls, path: Path, **overrides) -> Settings:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
        # Accept both [spektralia] section and top-level keys
        data = raw.get("spektralia", raw)
        data.update(overrides)
        # Coerce Path fields
        _coerce_paths(data)
        return cls(**data)

    def effective_hook_manifest_path(self) -> Path:
        """Resolve the hook-integrity manifest path, defaulting under state_dir."""
        if self.hook_manifest_path is not None:
            return self.hook_manifest_path
        return self.state_dir / "hook_manifest.json"

    def config_hash(self) -> str:
        """Deterministic hash of all policy-affecting settings.

        test_config_hash_covers_all_settings.py asserts every field is either
        included here or explicitly excluded in _non_policy.
        """
        non_policy = self._non_policy
        doc: dict = {}
        for f in fields(self):
            if f.name in non_policy:
                continue
            val = getattr(self, f.name)
            if isinstance(val, Path):
                val = str(val)
            doc[f.name] = val
        serialized = json.dumps(doc, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()
