"""Canonical JSON helpers for content-addressed Argus artifacts."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping


CANONICALIZATION_SPEC_VERSION = "argus-jcs-v1"
CANONICAL_RECORD_EXCLUDED_FIELDS = ("content_hash", "signature", "created_at")


@dataclass(frozen=True)
class CanonicalizationSpec:
    version: str
    json_profile: str
    excluded_record_fields: tuple[str, ...]


CANONICALIZATION_SPEC = CanonicalizationSpec(
    version=CANONICALIZATION_SPEC_VERSION,
    json_profile="JCS-style JSON: UTF-8, sorted keys, no insignificant whitespace, no NaN/Infinity",
    excluded_record_fields=CANONICAL_RECORD_EXCLUDED_FIELDS,
)


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes for a JSON-compatible value."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_record_payload(
    record: Mapping[str, Any],
    *,
    excluded_fields: tuple[str, ...] = CANONICAL_RECORD_EXCLUDED_FIELDS,
) -> dict[str, Any]:
    excluded = set(excluded_fields)
    return {key: value for key, value in record.items() if key not in excluded}


def canonical_record_bytes(
    record: Mapping[str, Any],
    *,
    spec: CanonicalizationSpec = CANONICALIZATION_SPEC,
) -> bytes:
    """Return versioned canonical bytes for C4-style record hashing vectors."""
    return canonical_json_bytes(canonical_record_payload(record, excluded_fields=spec.excluded_record_fields))
