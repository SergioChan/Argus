"""BLAKE3 hashing helpers for C4 content addressing."""

from __future__ import annotations

from typing import Any

from blake3 import blake3

from .canonical import canonical_json_bytes


BLAKE3_PREFIX = "blake3:"


def hash_bytes(payload: bytes) -> str:
    """Return a C4-style BLAKE3 content hash for raw bytes."""
    return f"{BLAKE3_PREFIX}{blake3(payload).hexdigest()}"


def hash_json(value: Any) -> str:
    """Return a C4-style BLAKE3 content hash for canonical JSON."""
    return hash_bytes(canonical_json_bytes(value))
