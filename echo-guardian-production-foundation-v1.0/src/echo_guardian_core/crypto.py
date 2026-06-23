from __future__ import annotations

from typing import Iterable

try:
    import blake3 as _blake3
except Exception as exc:  # pragma: no cover
    _blake3 = None
    _BLAKE3_IMPORT_ERROR = exc
else:
    _BLAKE3_IMPORT_ERROR = None


def blake3_hex(data: bytes) -> str:
    """Strict BLAKE3 hex digest. No fallback is permitted."""
    if _blake3 is None:
        raise RuntimeError(
            "BLAKE3 dependency is missing. Install requirements.txt. "
            "Echo Guardian does not allow silent hash fallback."
        ) from _BLAKE3_IMPORT_ERROR
    return _blake3.blake3(data).hexdigest()


def merkle_root_hex(leaf_hashes_hex: Iterable[str]) -> str:
    """Binary Merkle root using duplicate-last-leaf rule for odd levels."""
    level = list(leaf_hashes_hex)
    if not level:
        return blake3_hex(b"")
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[str] = []
        for i in range(0, len(level), 2):
            combined = bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])
            next_level.append(blake3_hex(combined))
        level = next_level
    return level[0]
