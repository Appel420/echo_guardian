from __future__ import annotations

import json
import unicodedata
from typing import Any

CANONICALIZATION = {"encoding": "canonical_json", "version": "0.2"}


def _normalize(obj: Any) -> Any:
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, list):
        return [_normalize(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, float):
        # Production audit envelopes should avoid floats because cross-platform
        # canonicalization can drift. Use integers/fixed-point in hashed material.
        raise TypeError("floats are prohibited in canonical audit material")
    return obj


def canonical_json_bytes(obj: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for hashing/signing."""
    normalized = _normalize(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
