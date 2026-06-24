from __future__ import annotations

import hashlib
from collections import OrderedDict
from typing import Any


class LRUCache:
    """In-memory LRU cache keyed on sha256(sanitized_text + config_hash)."""

    def __init__(self, maxsize: int = 1024) -> None:
        self._maxsize = maxsize
        self._store: OrderedDict[str, Any] = OrderedDict()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def make_key(sanitized_text: str, config_hash: str) -> str:
        return hashlib.sha256(
            (sanitized_text + config_hash).encode("utf-8")
        ).hexdigest()

    def get(self, key: str) -> Any | None:
        if key in self._store:
            self._store.move_to_end(key)
            self._hits += 1
            return self._store[key]
        self._misses += 1
        return None

    def set(self, key: str, value: Any) -> None:
        if key in self._store:
            self._store.move_to_end(key)
        else:
            if len(self._store) >= self._maxsize:
                self._store.popitem(last=False)
        self._store[key] = value

    def invalidate_all(self) -> None:
        self._store.clear()

    @property
    def stats(self) -> dict:
        return {
            "size": len(self._store),
            "maxsize": self._maxsize,
            "hits": self._hits,
            "misses": self._misses,
        }
