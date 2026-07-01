"""In-memory S8 artifact ledger semantics used by early M0 tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json_bytes
from .hashing import hash_bytes


class S8Error(Exception):
    """Base class for S8 semantic failures."""


class IncompleteLineageError(S8Error):
    """Raised when an artifact lacks required provenance lineage."""


class IllegalTierError(S8Error):
    """Raised when a promoted tier is not coupled to a validation report."""


class HashMismatchError(S8Error):
    """Raised when verify-on-read detects payload tampering."""


class WriteOnceViolationError(S8Error):
    """Raised when an existing artifact ref would be overwritten."""


@dataclass(frozen=True)
class Producer:
    subsystem: str
    version: str


@dataclass(frozen=True)
class Lineage:
    input_refs: tuple[str, ...]
    code_ref: str
    environment_digest: str
    seeds: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArtifactRecord:
    artifact_ref: str
    kind: str
    content_hash: str
    size_bytes: int
    producer: Producer
    lineage: Lineage
    claim_tier: str = "ran-toy"
    validation_report_ref: str | None = None


class InMemoryArtifactStore:
    """A small write-once C4 store for exercising S8 invariants."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        self._records: dict[str, ArtifactRecord] = {}

    def create_artifact(
        self,
        *,
        kind: str,
        payload: Any,
        producer: Producer,
        lineage: Lineage,
        claim_tier: str = "ran-toy",
        validation_report_ref: str | None = None,
    ) -> ArtifactRecord:
        self._assert_lineage_complete(lineage)
        self._assert_tier_coupled(claim_tier, validation_report_ref)

        payload_bytes = canonical_json_bytes(payload)
        content_hash = hash_bytes(payload_bytes)
        artifact_ref = f"c4://artifact/{content_hash.removeprefix('blake3:')}"
        if artifact_ref in self._records:
            existing = self._records[artifact_ref]
            if self._objects[artifact_ref] != payload_bytes:
                raise WriteOnceViolationError(f"artifact_ref already exists: {artifact_ref}")
            return existing

        record = ArtifactRecord(
            artifact_ref=artifact_ref,
            kind=kind,
            content_hash=content_hash,
            size_bytes=len(payload_bytes),
            producer=producer,
            lineage=lineage,
            claim_tier=claim_tier,
            validation_report_ref=validation_report_ref,
        )
        self._objects[artifact_ref] = payload_bytes
        self._records[artifact_ref] = record
        return record

    def get_artifact(self, artifact_ref: str) -> bytes:
        payload = self._objects[artifact_ref]
        record = self._records[artifact_ref]
        if hash_bytes(payload) != record.content_hash:
            raise HashMismatchError(f"hash mismatch for {artifact_ref}")
        return payload

    def get_record(self, artifact_ref: str) -> ArtifactRecord:
        self.get_artifact(artifact_ref)
        return self._records[artifact_ref]

    def __len__(self) -> int:
        return len(self._records)

    @staticmethod
    def _assert_lineage_complete(lineage: Lineage) -> None:
        if not lineage.code_ref:
            raise IncompleteLineageError("lineage.code_ref is required")
        if not lineage.environment_digest:
            raise IncompleteLineageError("lineage.environment_digest is required")

    @staticmethod
    def _assert_tier_coupled(claim_tier: str, validation_report_ref: str | None) -> None:
        if claim_tier != "ran-toy" and not validation_report_ref:
            raise IllegalTierError("tier above ran-toy requires validation_report_ref")
