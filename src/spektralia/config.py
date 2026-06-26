from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal

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

    # Internal path
    state_dir: Path = field(default_factory=lambda: Path.home() / ".spektralia")

    # Normalization
    normalization_map_version: int = 1

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
