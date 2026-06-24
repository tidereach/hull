from __future__ import annotations

import os
from dataclasses import dataclass, field

from .memory_safety import Secret
from .scanner import Detection


@dataclass
class Sanitized:
    """Result of sanitizing text. Token map is private."""

    text: str
    _token_map: dict[str, Secret] = field(default_factory=dict, repr=False, compare=False)

    def token_labels(self) -> list[str]:
        return list(self._token_map.keys())


def sanitize(text: str, detections: list[Detection]) -> Sanitized:
    """Replace detected spans with [REDACTED:LABEL:rand] tokens.

    Tokens are unique per-request (random 6-hex suffix).
    Originals are stored as Secret objects in the private token map.
    """
    if not detections:
        return Sanitized(text=text)

    # Sort by start position, remove duplicates
    sorted_dets = sorted(set(detections), key=lambda d: d.start)

    token_map: dict[str, Secret] = {}
    used_suffixes: set[str] = set()
    result: list[str] = []
    prev_end = 0

    for det in sorted_dets:
        start, end = det.start, det.end
        if start < prev_end:
            # Overlapping — skip (deduplication should have handled this)
            continue
        if start > len(text) or end > len(text):
            continue

        # Emit text before this detection
        result.append(text[prev_end:start])

        # Generate unique random suffix
        for _ in range(100):
            suffix = os.urandom(3).hex()
            if suffix not in used_suffixes:
                break
        used_suffixes.add(suffix)

        token = f"[REDACTED:{det.label}:{suffix}]"
        original_value = text[start:end]
        token_map[token] = Secret(original_value.encode("utf-8"), label=det.label)

        result.append(token)
        prev_end = end

    result.append(text[prev_end:])

    return Sanitized(text="".join(result), _token_map=token_map)


def _parse_path(path: str) -> list[str | int]:
    """Parse a JSONPath string into a list of segments.

    Supported forms:
      $          → []  (root, matches the payload itself)
      $.field    → ["field"]
      $.a.b      → ["a", "b"]
      $[i]       → [i]  (integer index)
      $.a[*]     → ["a", "*"]
      $.*        → ["*"]  (wildcard at root)

    Returns a list of segments (str for dict keys, int for list indices,
    "*" for list wildcard).
    """
    if path in ("$", "$.*"):
        return []  # special: root / "all" — handled separately for str payloads

    # Strip leading "$"
    remainder = path[1:]  # e.g. ".user.email" or "[0]" or ".a[*]"

    segments: list[str | int] = []
    i = 0
    while i < len(remainder):
        ch = remainder[i]
        if ch == ".":
            # Read until next "." or "["
            j = i + 1
            while j < len(remainder) and remainder[j] not in (".", "["):
                j += 1
            seg = remainder[i + 1:j]
            if seg == "*":
                segments.append("*")
            else:
                segments.append(seg)
            i = j
        elif ch == "[":
            # Read until "]"
            j = i + 1
            while j < len(remainder) and remainder[j] != "]":
                j += 1
            inner = remainder[i + 1:j]
            if inner == "*":
                segments.append("*")
            else:
                segments.append(int(inner))
            i = j + 1  # skip past "]"
        else:
            # Shouldn't happen with valid paths, skip
            i += 1

    return segments


def _replace_tokens_in_str(value: str, token_map: dict[str, "Secret"]) -> tuple[str, list[str]]:
    """Replace all tokens found in value. Returns (new_str, list_of_consumed_tokens)."""
    consumed = []
    for token in list(token_map.keys()):
        if token in value:
            secret = token_map[token]
            value = value.replace(token, secret.as_str())
            consumed.append(token)
    return value, consumed


def _restore_recursive(
    obj: dict | list | str,
    token_map: dict[str, "Secret"],
    path_segments_list: list[list[str | int]],
    current_path: list[str | int],
) -> dict | list | str:
    """Recursively traverse obj, replacing tokens only at target paths.

    path_segments_list: list of parsed path segment lists to match
    current_path: the path taken to reach this node
    """
    if isinstance(obj, str):
        # Check if current_path matches any of the target paths
        for segments in path_segments_list:
            if current_path == segments:
                new_val, consumed = _replace_tokens_in_str(obj, token_map)
                for token in consumed:
                    secret = token_map.pop(token)
                    secret.wipe()
                return new_val
        return obj

    elif isinstance(obj, dict):
        new_dict = {}
        for key, val in obj.items():
            # Check if this key is targeted by a wildcard or exact match
            child_path = current_path + [key]
            # Also check if any path has a wildcard "*" at this level
            new_dict[key] = _restore_recursive(val, token_map, path_segments_list, child_path)
        return new_dict

    elif isinstance(obj, list):
        new_list = []
        for idx, val in enumerate(obj):
            child_path = current_path + [idx]
            # Check if any path uses "*" at this list level
            # by substituting idx with "*" — handled in _restore_recursive for str leaves
            # We also need to check wildcard: if path is [..., "*"] and child_path matches
            # up to the parent, the wildcard matches any index
            new_list.append(_restore_recursive(val, token_map, path_segments_list, child_path))
        return new_list

    else:
        return obj


def _path_matches(current_path: list[str | int], segments: list[str | int]) -> bool:
    """Check if current_path matches the given segment pattern (supports '*' wildcard)."""
    if len(current_path) != len(segments):
        return False
    for cur, seg in zip(current_path, segments):
        if seg == "*":
            continue  # wildcard matches any key/index
        if cur != seg:
            return False
    return True


def _restore_recursive_v2(
    obj: dict | list | str,
    token_map: dict[str, "Secret"],
    path_segments_list: list[list[str | int]],
    current_path: list[str | int],
) -> dict | list | str:
    """Recursively traverse obj, replacing tokens only at matching paths."""
    if isinstance(obj, str):
        # Check if current_path matches any of the target paths
        for segments in path_segments_list:
            if _path_matches(current_path, segments):
                new_val, consumed = _replace_tokens_in_str(obj, token_map)
                for token in consumed:
                    secret = token_map.pop(token)
                    secret.wipe()
                return new_val
        return obj

    elif isinstance(obj, dict):
        new_dict = {}
        for key, val in obj.items():
            child_path = current_path + [key]
            new_dict[key] = _restore_recursive_v2(val, token_map, path_segments_list, child_path)
        return new_dict

    elif isinstance(obj, list):
        new_list = []
        for idx, val in enumerate(obj):
            child_path = current_path + [idx]
            new_list.append(_restore_recursive_v2(val, token_map, path_segments_list, child_path))
        return new_list

    else:
        return obj


def _restore(
    payload: dict | list | str,
    sanitized: Sanitized,
    *,
    unsafe_restore_paths: list[str],
) -> dict | list | str:
    """Private restoration API. Single-use; consumed tokens are wiped and removed.

    unsafe_restore_paths: list of JSONPath expressions identifying where to restore.
    Supported: "$", "$.*", "$.field", "$.a.b", "$[i]", "$.a[*]"

    Only for tests and explicit integrators; never called from public API.
    """
    token_map = sanitized._token_map

    # Handle flat string payloads
    if isinstance(payload, str):
        # Restore all tokens if any path is "$" or "$.*"
        if any(p in ("$", "$.*") for p in unsafe_restore_paths):
            result = payload
            for token in list(token_map.keys()):
                if token in result:
                    secret = token_map.pop(token)
                    result = result.replace(token, secret.as_str())
                    secret.wipe()
            return result
        else:
            return payload

    # Parse all paths into segment lists (exclude "$" and "$.*" — root paths)
    path_segments_list = []
    for p in unsafe_restore_paths:
        if p in ("$", "$.*"):
            continue  # root paths only apply to str payloads
        segs = _parse_path(p)
        path_segments_list.append(segs)

    return _restore_recursive_v2(payload, token_map, path_segments_list, [])
